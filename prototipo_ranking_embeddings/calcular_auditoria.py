# -*- coding: utf-8 -*-
"""
Recomputes precision/recall/F1 from the HUMAN labels of the audited worklist.

Workflow:
  1. montar_worklist_auditoria.py  -> generates auditoria_negativos_worklist.csv
  2. THE REVIEWER fills the `veredito_humano` column (VULNERAVEL | CORRIGIDO) by
     comparing the two links (fix commit x file in the fork). CORRIGIDO means the
     negative was mislabelled -- the fork already had the fix; VULNERAVEL means it is
     a valid negative.
  3. calcular_auditoria.py         -> final metrics (audited negatives + the reliable
     positives from precision_eval.json).
"""
import os, sys, json, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
WL = os.path.join(HERE, "auditoria_negativos_worklist.csv")
EVAL = os.path.join(HERE, "resultados_2026-07-09", "precision_eval.json")


def load_worklist():
    with open(WL, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def metrics(items):
    """items: lista de (pred_corrigido: bool, actual_patched: bool)."""
    TP = sum(1 for p, a in items if p and a)
    FP = sum(1 for p, a in items if p and not a)
    FN = sum(1 for p, a in items if not p and a)
    TN = sum(1 for p, a in items if not p and not a)
    P = TP / (TP + FP) if TP + FP else 1.0
    R = TP / (TP + FN) if TP + FN else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    return dict(TP=TP, FP=FP, FN=FN, TN=TN, precision=round(P, 3),
                recall=round(R, 3), f1=round(F, 3))


def main():
    wl = load_worklist()
    filled = [r for r in wl if r.get("veredito_humano", "").strip().upper() in ("VULNERAVEL", "CORRIGIDO")]
    print(f"Worklist: {len(wl)} negativos | preenchidos: {len(filled)} | pendentes: {len(wl) - len(filled)}")
    if not filled:
        print("\nNada preenchido ainda. Abra auditoria_negativos_worklist.csv, preencha")
        print("'veredito_humano' (VULNERAVEL|CORRIGIDO) nos casos DISPUTADO e rode de novo.")
        return
    relabel = sum(1 for r in filled if r["veredito_humano"].strip().upper() == "CORRIGIDO")
    print(f"Negativos que a auditoria reclassificou como CORRIGIDO (rótulo ruim): {relabel}")

    # positivos confiáveis do precision_eval
    pos = []
    for x in json.load(open(EVAL, encoding="utf-8"))["instancias"]:
        if x["label"] != "PATCHED":
            continue
        emb = x["emb_sp"] is not None and (x["emb_sp"] - x["emb_sv"]) > 0
        ast = x["ast_sim_patch"] is not None and x["ast_sim_patch"] >= 0.80
        pos.append((emb, ast, True))

    def col(method):
        items = []
        for r in filled:                       # negativos auditados (label = humano)
            actual = r["veredito_humano"].strip().upper() == "CORRIGIDO"
            pv = r[f"verdito_{method}"].strip().upper() == "CORRIGIDO" if method != "comb" else \
                (r["verdito_embeddings"].strip().upper() == "CORRIGIDO" or
                 r["verdito_ast2a"].strip().upper() == "CORRIGIDO")
            items.append((pv, actual))
        for emb, ast, actual in pos:           # positivos confiáveis
            pv = emb if method == "embeddings" else ast if method == "ast2a" else (emb or ast)
            items.append((pv, actual))
        return metrics(items)

    print("\n=== Métricas com negativos AUDITADOS + positivos confiáveis ===")
    for name, key in [("Embeddings", "embeddings"), ("AST 2A", "ast2a"),
                      ("Combinador (AST2A ∪ emb)", "comb")]:
        m = col(key)
        print(f"  {name:<26} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}  "
              f"(TP{m['TP']} FP{m['FP']} FN{m['FN']} TN{m['TN']})")

    out = {"n_negativos_auditados": len(filled), "n_reclassificados_corrigido": relabel,
           "metodos": {k: col(k) for k in ["embeddings", "ast2a", "comb"]}}
    p = os.path.join(HERE, "resultados_2026-07-09", "auditoria_metricas.json")
    json.dump(out, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\n-> {p}")


if __name__ == "__main__":
    main()
