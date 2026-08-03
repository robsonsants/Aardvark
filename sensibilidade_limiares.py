# -*- coding: utf-8 -*-
"""Threshold sensitivity of Layers 2A and 2B.

Answers whether the reported conclusions are an artefact of the chosen thresholds.
Runs fully offline over the versioned results -- no network, no token.

Source 1: precision_eval.json (100 two-class instances, carrying ast_sim_patch and
          ast_sim_vuln per instance) -> Precision/Recall/F1 as thresholds vary
Source 2: dissertation_resultados.json + gt_v2_resultados.json (43 pairs, all PATCHED)
          -> recall as the patched threshold varies

Note: the recall re-derived here aggregates `sha_match OR sim_2a >= tau` directly,
without the _STATUS_PRIORITY table of pipeline_dissertation.py, so its absolute value
differs slightly from the published figure. The shape of the curve is the same, which
is what the sensitivity argument rests on.
"""
import json, os, sys, io, collections

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
BASE = os.path.dirname(os.path.abspath(__file__))

P = json.load(open(os.path.join(BASE, "prototipo_ranking_embeddings",
                                "resultados_2026-07-09", "precision_eval.json"),
                   encoding="utf-8"))["instancias"]


def prf(pred, gold):
    tp = sum(1 for p, g in zip(pred, gold) if p and g)
    fp = sum(1 for p, g in zip(pred, gold) if p and not g)
    fn = sum(1 for p, g in zip(pred, gold) if not p and g)
    tn = sum(1 for p, g in zip(pred, gold) if not p and not g)
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return pr, rc, f1, (tp, fp, fn, tn)


gold = [i["label"] == "PATCHED" for i in P]

print("=" * 78)
print("C5.a — Camada 2A: varredura do limiar CORRIGIDO (tau_hi), tau_lo=0,35")
print("       conjunto de 2 classes (n=100: 44 pos / 56 neg)")
print("=" * 78)
print(f"{'tau_hi':>7} {'P':>6} {'R':>6} {'F1':>6}   TP/FP/FN/TN   {'%incerteza':>10}")
for hi in [0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
    pred = [i["ast_sim_patch"] >= hi for i in P]
    inc = sum(1 for i in P if 0.35 < i["ast_sim_patch"] < hi)
    pr, rc, f1, c = prf(pred, gold)
    mark = "  <- atual" if abs(hi - 0.80) < 1e-9 else ""
    print(f"{hi:>7.2f} {pr:6.3f} {rc:6.3f} {f1:6.3f}   {c[0]:>2}/{c[1]:>2}/{c[2]:>2}/{c[3]:>2}   "
          f"{100*inc/len(P):9.1f}%{mark}")

print()
print("=" * 78)
print("C5.b — Camada 2A: varredura do limiar NAO CORRIGIDO (tau_lo), tau_hi=0,80")
print("=" * 78)
print(f"{'tau_lo':>7} {'%zona incerteza':>16} {'%NAO CORRIGIDO':>16}")
for lo in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
    inc = sum(1 for i in P if lo < i["ast_sim_patch"] < 0.80)
    neg = sum(1 for i in P if i["ast_sim_patch"] <= lo)
    mark = "  <- atual" if abs(lo - 0.35) < 1e-9 else ""
    print(f"{lo:>7.2f} {100*inc/len(P):15.1f}% {100*neg/len(P):15.1f}%{mark}")

print()
print("=" * 78)
print("C5.c — Camada 2B: varredura da margem |delta| (delta = sim_pos - sim_pre)")
print("=" * 78)
print(f"{'margem':>7} {'P':>6} {'R':>6} {'F1':>6}   TP/FP/FN/TN   {'%incerteza':>10}")
for m in [0.00, 0.02, 0.05, 0.08, 0.10, 0.15, 0.20]:
    pred, inc = [], 0
    for i in P:
        d = i["ast_sim_patch"] - i["ast_sim_vuln"]
        if abs(d) <= m:
            pred.append(False)
            inc += 1
        else:
            pred.append(d > 0)
    pr, rc, f1, c = prf(pred, gold)
    mark = "  <- atual" if abs(m - 0.05) < 1e-9 else ""
    print(f"{m:>7.2f} {pr:6.3f} {rc:6.3f} {f1:6.3f}   {c[0]:>2}/{c[1]:>2}/{c[2]:>2}/{c[3]:>2}   "
          f"{100*inc/len(P):9.1f}%{mark}")

# ---------------------------------------------------------------- GT v2 (43 pares)
D = json.load(open(os.path.join(BASE, "resultados_2026-07-04",
                                "dissertation_resultados.json"), encoding="utf-8"))
V2 = json.load(open(os.path.join(BASE, "resultados_2026-07-04",
                                 "gt_v2_resultados.json"), encoding="utf-8"))
gt = {(r["fork"], r["cve"]): r["gt_v2"] for r in V2}

por_par = collections.defaultdict(list)
for r in D:
    por_par[(r["fork"], r["cve_id"])].append(r)

print()
print("=" * 78)
print("C5.d — Recall da Camada 2A nos pares do GT v2 (uniao por CVE), tau_hi variavel")
print(f"       pares com dados de similaridade: {len(set(por_par) & set(gt))} de {len(gt)}")
print("=" * 78)
print(f"{'tau_hi':>7} {'recall':>7} {'TP':>4} {'zona incerteza (pares)':>24}")
for hi in [0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
    tp = inc = tot = 0
    for k, rows in por_par.items():
        if gt.get(k) != "PATCHED":
            continue
        tot += 1
        sims = [r.get("sim_2a") or 0.0 for r in rows]
        shas = any(r.get("sha_match") for r in rows)
        if shas or max(sims) >= hi:
            tp += 1
        elif max(sims) > 0.35:
            inc += 1
    mark = "  <- atual" if abs(hi - 0.80) < 1e-9 else ""
    print(f"{hi:>7.2f} {tp/tot:7.3f} {tp:>4} {inc:>24}{mark}")
print(f"(total de pares PATCHED avaliados: {tot})")
