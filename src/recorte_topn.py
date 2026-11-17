#!/usr/bin/env python3
"""Derive a --top N cut from a run executed with a larger N.

Why this exists instead of running the pipeline three times: select_top_forks()
walks the forks ordered by pushed_at and keeps the first N with ahead_by > 0,
so top 3 is a prefix of top 5, which is a prefix of top 10 — provided the three
cuts come from the SAME fork snapshot. Re-running --top 3 days later would
re-select forks (the pipeline warns the selection is dynamic) and the cuts would
no longer be comparable. Deriving is therefore both cheaper and methodologically
tighter: one snapshot, three nested populations.

Per-pair verdicts do not depend on N, so only the aggregates are recomputed.
"""
import argparse, json, os, sys, csv, collections, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import pipeline_dissertation as pd


def ordem_dos_forks(rows):
    """Selection order = order of first appearance in the raw result lines."""
    ordem = collections.defaultdict(list)
    for r in rows:
        lst = ordem[r["upstream"]]
        if r["fork"] not in lst:
            lst.append(r["fork"])
    return ordem


def kappa(tp, fp, fn, tn):
    n = tp + fp + fn + tn
    if n == 0:
        return 0.0
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
    return 0.0 if pe == 1 else round((po - pe) / (1 - pe), 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="pasta do run de origem (o N maior)")
    ap.add_argument("--top", type=int, required=True)
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args()

    src = os.path.abspath(a.run)
    out = os.path.abspath(a.outdir)
    os.makedirs(out, exist_ok=True)

    rows = json.load(open(os.path.join(src, "dissertation_resultados.json"), encoding="utf-8"))
    ordem = ordem_dos_forks(rows)
    manter = {u: set(v[: a.top]) for u, v in ordem.items()}
    recorte = [r for r in rows if r["fork"] in manter[r["upstream"]]]

    verdicts = pd.aggregate_verdicts(recorte)
    coverage = pd.compute_coverage(verdicts)
    if isinstance(coverage, dict):
        coverage = sorted(coverage.values(), key=lambda x: x["cobertura_pct"], reverse=True)
    metrics = pd.compute_metrics(verdicts, coverage)

    cwd = os.getcwd()
    os.chdir(out)
    try:
        pd.save_results(recorte, verdicts, coverage, metrics)
    finally:
        os.chdir(cwd)

    forks = {r["fork"] for r in recorte}
    print(f"\n=== RECORTE top {a.top} (derivado de {os.path.basename(src)}) ===")
    print(f"  upstreams   : {len({r['upstream'] for r in recorte})}")
    print(f"  forks       : {len(forks)}  (de {len({r['fork'] for r in rows})})")
    print(f"  linhas cruas: {len(recorte)}  (de {len(rows)})")
    print(f"  pares       : {len(verdicts)}")
    print(f"  cobertura   : {metrics.get('cobertura_media_pct')}%")

    # ---- ground truth, se existir no run de origem ----
    gtp = os.path.join(src, "gt_dissertation_metricas.json")
    if os.path.exists(gtp):
        gt = json.load(open(gtp, encoding="utf-8"))
        pares = [p for p in gt.get("pares", []) if p["chave"].split("::")[1] in forks]
        tp = sum(1 for p in pares if p["pred_corrigido"] and p["gt"] == "CONFIRMED_PATCHED")
        fp = sum(1 for p in pares if p["pred_corrigido"] and p["gt"] == "CONFIRMED_VULNERABLE")
        fn = sum(1 for p in pares if not p["pred_corrigido"] and p["gt"] == "CONFIRMED_PATCHED")
        tn = sum(1 for p in pares if not p["pred_corrigido"] and p["gt"] == "CONFIRMED_VULNERABLE")
        prec = round(tp / (tp + fp), 4) if tp + fp else 0.0
        rec = round(tp / (tp + fn), 4) if tp + fn else 0.0
        f1 = round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0
        acc = round((tp + tn) / len(pares), 4) if pares else 0.0
        novo = dict(gt)
        novo.update({"n_com_gt_conclusivo": len(pares), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                     "precision": prec, "recall": rec, "f1_score": f1, "accuracy": acc,
                     "kappa_cohen": kappa(tp, fp, fn, tn), "pares": pares,
                     "nota_recorte": f"derivado de {os.path.basename(src)} com --top {a.top}"})
        json.dump(novo, open(os.path.join(out, "gt_dissertation_metricas.json"), "w", encoding="utf-8"),
                  indent=2, ensure_ascii=False)
        # linhas cruas do GT, que o experimento_regra_ab.py consome
        gtr = os.path.join(src, "gt_dissertation_resultados.json")
        if os.path.exists(gtr):
            linhas = [r for r in json.load(open(gtr, encoding="utf-8")) if r["fork"] in forks]
            json.dump(linhas, open(os.path.join(out, "gt_dissertation_resultados.json"), "w",
                                   encoding="utf-8"), indent=2, ensure_ascii=False)
            print(f"  GT (linhas) : {len(linhas)}")

        print(f"  GT          : n={len(pares)}  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"                P {prec}  R {rec}  F1 {f1}  kappa {novo['kappa_cohen']}")
    print(f"\n-> {out}")


if __name__ == "__main__":
    main()
