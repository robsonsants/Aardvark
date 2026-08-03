# -*- coding: utf-8 -*-
"""
PRECISION/RECALL against a negative set, evaluation of the AST+embeddings COMBINER,
and CALIBRATION of the decision margin.

Two-class labelled set, built by construction:
  POSITIVES (PATCHED)    = upstream@fix + forks confirmed patched (HEAD, ground truth).
  NEGATIVES (VULNERABLE) = upstream@pre + each fork at its PRE-ADOPTION version
     (the last commit touching the file BEFORE the upstream fix date -- it could not
      have adopted a fix that did not exist yet, so it is vulnerable by construction).

Each instance gets a verdict from the AST layers (2A and 2B, via pipeline_core) and
from embeddings (UniXcoder). We then evaluate: AST alone, embeddings alone, and the
COMBINER (AST=patched OR embeddings=patched). Real Precision/Recall/F1 plus a sweep
over the embedding margin.

Caveat carried into the paper: pre-adoption negatives are noisy, so the aggregate
precision reported from this set is a FLOOR, not a point estimate.
"""
import sys, os, json, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass
import run_ecosystem as R
import pipeline_core as pc
from unixcoder_embed import UniXcoder


def fork_pre_file(fork, path, before_iso):
    j = R.api(f"https://api.github.com/repos/{fork}/commits",
              params={"path": path, "until": before_iso, "per_page": 1})
    if j and isinstance(j, list) and j:
        return R.get_file(fork, path, j[0]["sha"])
    return None


def ast_sims(instance_code, refv_ast, refp_ast, lang):
    tgt = pc.parse_code(instance_code, lang)
    if tgt is None or refv_ast is None or refp_ast is None:
        return None, None
    sp = pc.compute_sim(refp_ast, tgt)[2]
    sv = pc.compute_sim(refv_ast, tgt)[2]
    return sp, sv


def main():
    rows = json.load(open(R.RESULTS, encoding="utf-8"))
    gt = {p["chave"] for p in json.load(open(R.GT_METRICS, encoding="utf-8"))["pares"]}
    tasks = {}
    for r in rows:
        if r.get("status") == "FILE_NOT_FOUND" or not r.get("filepath"):
            continue
        key = (r["upstream"], r["cve_id"], r["fix_sha"], r["filepath"])
        tasks.setdefault(key, {"lang": R.lang_of(r["filepath"], r.get("language", "")),
                               "forks": set()})["forks"].add(r["fork"])

    print("Carregando UniXcoder...")
    model = UniXcoder()
    instances = []

    for (upstream, cve, fix_sha, path), info in sorted(tasks.items()):
        lang = info["lang"]
        refs = R.build_refs(upstream, fix_sha, path, lang, model)
        if not refs:
            continue
        target, ev, ep, sanity, pre_file, post_file = refs
        if not target:
            continue
        vuln_fn = R.tse.function_by_name(pre_file, lang, target)
        patch_fn = R.tse.function_by_name(post_file, lang, target)
        if not vuln_fn or not patch_fn:
            continue
        refv_ast = pc.parse_code(vuln_fn["text"], lang)
        refp_ast = pc.parse_code(patch_fn["text"], lang)
        commit = R.get_commit(upstream, fix_sha)
        fix_date = commit["commit"]["committer"]["date"]
        # tipo de patch (para a calibração do passo 3)
        adds = sum(1 for f in commit.get("files", []) if f.get("filename") == path
                   for _ in [0]) and None
        pf = next((f for f in commit.get("files", []) if f.get("filename") == path), {})
        ptype = "adicao" if (pf.get("additions", 0) > 2 * max(1, pf.get("deletions", 0))) else "remocao/mista"

        def add(source, label, fork, code):
            if not code:
                return
            fn = R.tse.function_by_name(code, lang, target)
            fcode = fn["text"] if fn else code
            sv, sp = R.score(fcode, ev, ep, model)               # embeddings
            a_sp, a_sv = ast_sims(fcode, refv_ast, refp_ast, lang)  # AST 2A/2B
            instances.append({
                "upstream": upstream, "cve": cve, "fork": fork, "source": source,
                "label": label, "lang": lang, "target": target, "patch_type": ptype,
                "emb_sv": round(sv, 4), "emb_sp": round(sp, 4),
                "ast_sim_patch": round(a_sp, 4) if a_sp is not None else None,
                "ast_sim_vuln": round(a_sv, 4) if a_sv is not None else None,
            })

        # positivos
        add("upstream_fix", "PATCHED", upstream, post_file)
        for fk in sorted(info["forks"]):
            if f"{upstream}::{fk}::{cve}" in gt:
                add("fork_head", "PATCHED", fk, R.get_file(fk, path))
        # negativos
        add("upstream_pre", "VULNERABLE", upstream, pre_file)
        for fk in sorted(info["forks"]):
            add("fork_pre", "VULNERABLE", fk, fork_pre_file(fk, path, fix_date))

    # ---------- predicados ----------
    def emb_pred(m):
        return lambda x: (x["emb_sp"] - x["emb_sv"]) > m
    def ast2a_pred(x):
        return x["ast_sim_patch"] is not None and x["ast_sim_patch"] >= pc.THRESHOLD_HIGH
    def ast2b_pred(x):
        return (x["ast_sim_patch"] is not None and
                pc.classify_dual(x["ast_sim_patch"], x["ast_sim_vuln"])[0] == "CORRIGIDO")

    def metrics(pred, subset=None):
        data = subset if subset is not None else instances
        TP = FP = FN = TN = 0
        for x in data:
            p = pred(x); pos = x["label"] == "PATCHED"
            TP += p and pos; FP += p and not pos; FN += (not p) and pos; TN += (not p) and not pos
        prec = TP / (TP + FP) if TP + FP else 1.0
        rec = TP / (TP + FN) if TP + FN else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return dict(TP=TP, FP=FP, FN=FN, TN=TN, precision=round(prec, 3),
                    recall=round(rec, 3), f1=round(f1, 3))

    # ---------- passo 3: calibração de margem ----------
    grid = [0.0, 0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10]
    sweep = [{"margem": m, **metrics(emb_pred(m))} for m in grid]
    best = max(sweep, key=lambda s: (s["f1"], s["recall"]))
    bm = best["margem"]

    # combinador no melhor ponto de margem
    def comb_pred(x):
        return ast2a_pred(x) or emb_pred(bm)(x)

    npos = sum(1 for x in instances if x["label"] == "PATCHED")
    nneg = len(instances) - npos
    result = {
        "n_instancias": len(instances), "n_positivos": npos, "n_negativos": nneg,
        "metodos": {
            "AST_2A": metrics(ast2a_pred),
            "AST_2B_dupla_ref": metrics(ast2b_pred),
            f"embeddings_margem_{bm}": metrics(emb_pred(bm)),
            f"COMBINADOR_AST2A_ou_emb_{bm}": metrics(comb_pred),
        },
        "calibracao_margem_embeddings": sweep,
        "melhor_margem": bm,
        "embeddings_por_tipo_patch": {
            "adicao": metrics(emb_pred(bm), [x for x in instances if x["patch_type"] == "adicao"]),
            "remocao/mista": metrics(emb_pred(bm), [x for x in instances if x["patch_type"] != "adicao"]),
        },
        "instancias": instances,
    }
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          f"resultados_{datetime.date.today().isoformat()}")
    os.makedirs(outdir, exist_ok=True)
    json.dump(result, open(os.path.join(outdir, "precision_eval.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print(f"\nInstâncias: {len(instances)}  (positivos={npos}, negativos={nneg})")
    print("\n=== Calibração da margem (embeddings) ===")
    print(f"{'margem':>7} {'P':>6} {'R':>6} {'F1':>6}  TP/FP/FN/TN")
    for s in sweep:
        star = "  <- melhor" if s["margem"] == bm else ""
        print(f"{s['margem']:>7} {s['precision']:>6} {s['recall']:>6} {s['f1']:>6}  "
              f"{s['TP']}/{s['FP']}/{s['FN']}/{s['TN']}{star}")
    print(f"\n=== Precision/Recall/F1 por método (margem emb = {bm}) ===")
    for name, m in result["metodos"].items():
        print(f"  {name:<32} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}  "
              f"(TP{m['TP']} FP{m['FP']} FN{m['FN']} TN{m['TN']})")
    print("\n=== Embeddings por tipo de patch ===")
    for t, m in result["embeddings_por_tipo_patch"].items():
        print(f"  {t:<14} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"(TP{m['TP']} FP{m['FP']} FN{m['FN']} TN{m['TN']})")
    print(f"\n-> {os.path.join(outdir, 'precision_eval.json')}")
    return result, outdir


if __name__ == "__main__":
    main()
