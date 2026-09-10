#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sensibilidade_regras.py - sensitivity sweep over the decision thresholds
==================================================================================
Sweeps the three parameters that turn measurements into verdicts and reports how each
one moves precision, recall, F1, Kappa and coverage:

  - THRESHOLD_HIGH / THRESHOLD_LOW : the Layer 2A thresholds (0.80 / 0.35)
  - MARGIN_ZI                      : the Layer 2B uncertainty margin (0.05)
  - SIM_MINIMA_2B                  : the absolute similarity floor of guard B (0.60)

WHY IT IS OFFLINE
None of these thresholds changes a MEASUREMENT: sim_2a, sim_patch, sim_vuln and delta
are already stored in the run's raw records. The thresholds only change how those
numbers become a label and how labels become a verdict, so the sweep is an exact
re-derivation - no network, no token.

ZSS_NODE_LIMIT (600 nodes) is deliberately NOT swept here: it decides WHICH metric is
computed, so moving it requires reprocessing the ASTs over evidencias_dissertacao/.

Replaces sensibilidade_limiares.py from the July snapshot, which covered Layer 2A only
and read the (now inactive) embedding prototype.

Usage:
    python sensibilidade_regras.py --run resultados_2026-08-31_v2
Output:
    <run>/sensibilidade_limiares.json
"""

import argparse, json, os, sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_core as pc
import pipeline_dissertation as pdis

DEF = dict(thr_high=pc.THRESHOLD_HIGH, thr_low=pc.THRESHOLD_LOW,
           margin=pc.MARGIN_ZI, sim_min_2b=pdis.SIM_MINIMA_2B)


def redecidir(linhas, thr_high, thr_low, margin, sim_min_2b, regra_ab):
    """Re-deriva o status de cada linha com os limiares dados.

    RESSALVA DE PRECISAO: sim_2a/sim_patch/sim_vuln sao gravados arredondados no
    JSON. Num caso de borda (sim_2a real 0.7996 gravado como 0.8) a re-derivacao
    inverteria o rotulo em relacao ao run. Por isso, quando o limiar varrido E o
    proprio limiar do pipeline, o rotulo GRAVADO prevalece — assim o baseline
    reproduz o run exatamente. Fora do valor padrao, recalcula.
    """
    pdis.SIM_MINIMA_2B = sim_min_2b
    padrao_2a = (thr_high == pc.THRESHOLD_HIGH and thr_low == pc.THRESHOLD_LOW)
    padrao_2b = (margin == pc.MARGIN_ZI)
    out = []
    for r in linhas:
        novo = dict(r)
        if r["sha_match"] or r["status"] == "FILE_NOT_FOUND":
            out.append(novo); continue

        sim_2a = r.get("sim_2a")
        if sim_2a is None:
            l2a = r.get("label_2a")
        elif sim_2a >= thr_high:      l2a = "CORRIGIDO"
        elif sim_2a <= thr_low:       l2a = "NAO_CORRIGIDO"
        else:                         l2a = "ZONA_INCERTEZA"
        if padrao_2a and r.get("label_2a"):
            l2a = r["label_2a"]

        sp, sv = r.get("sim_patch"), r.get("sim_vuln")
        if sp is None or sv is None:
            l2b, delta = r.get("label_2b"), r.get("delta")
        else:
            delta = sp - sv
            l2b = ("CORRIGIDO" if delta > margin else
                   "VULNERAVEL" if delta < -margin else "ZONA_INCERTEZA")
        if padrao_2b and r.get("label_2b"):
            l2b, delta = r["label_2b"], r.get("delta", delta)

        novo["label_2a"], novo["label_2b"], novo["delta"] = l2a, l2b, delta
        novo["status"] = pdis.decidir_status(l2a, l2b, sim_2a, delta, regra_ab=regra_ab)
        out.append(novo)
    return out


def avaliar(linhas, rotulos_gt, **kw):
    regra_ab = kw.pop("regra_ab", False)
    lin = redecidir(linhas, regra_ab=regra_ab, **kw)
    verdicts = pdis.aggregate_verdicts(lin)
    cob = pdis.compute_coverage(verdicts)
    met = pdis.compute_metrics(verdicts, cob)
    por_par = {(v["fork"], v["cve_id"]): v["status"] for v in verdicts}

    tp = fp = fn = tn = 0
    for par, rot in rotulos_gt.items():
        auto = por_par.get(par, "") == "CORRIGIDO"
        real = rot == "CONFIRMED_PATCHED"
        if auto and real: tp += 1
        elif auto:        fp += 1
        elif real:        fn += 1
        else:             tn += 1
    p = tp / (tp + fp) if tp + fp else None
    r_ = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r_ / (p + r_) if p and r_ else None
    return dict(TP=tp, FP=fp, FN=fn, TN=tn,
                P=None if p is None else round(p, 4),
                R=None if r_ is None else round(r_, 4),
                F1=None if f1 is None else round(f1, 4),
                cobertura=met["cobertura_media_pct"],
                n_corrigidas=met["n_corrigidas"],
                n_incerteza=met["n_zona_incerteza"])


def frange(a, b, passo):
    v, out = a, []
    while v <= b + 1e-9:
        out.append(round(v, 4)); v += passo
    return out


def tabela(titulo, coluna, linhas_tab, destaque=None):
    print("\n" + titulo)
    print("  %-8s %4s %3s %4s %3s  %-7s %-7s %-7s %-9s" %
          (coluna, "TP", "FP", "FN", "TN", "P", "R", "F1", "cobert.%"))
    for val, m in linhas_tab:
        marca = " <<< atual" if destaque is not None and abs(val - destaque) < 1e-9 else ""
        print("  %-8s %4d %3d %4d %3d  %-7s %-7s %-7s %-9s%s" %
              (val, m["TP"], m["FP"], m["FN"], m["TN"], m["P"], m["R"], m["F1"],
               m["cobertura"], marca))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--outdir", default=None)
    args = ap.parse_args()
    base = Path(args.run)
    out = Path(args.outdir) if args.outdir else base

    linhas = json.load(open(base / "dissertation_resultados.json", encoding="utf-8"))
    rotulos = {}
    for g in json.load(open(base / "gt_dissertation_resultados.json", encoding="utf-8")):
        if g["gt_label"] in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
            rotulos[(g["fork"], g["cve"])] = g["gt_label"]

    print(f"Run: {base}  ({len(linhas)} linhas, {len(rotulos)} pares com GT conclusivo)")

    # sanidade: com os limiares atuais tem de reproduzir o run publicado
    base_uniao = avaliar(linhas, rotulos, regra_ab=False, **DEF)
    base_ab    = avaliar(linhas, rotulos, regra_ab=True,  **DEF)
    print(f"\nReproducao do run publicado (uniao): P={base_uniao['P']} R={base_uniao['R']} "
          f"F1={base_uniao['F1']} cobertura={base_uniao['cobertura']}%  FP={base_uniao['FP']}")
    print(f"Regra A+B nos limiares atuais      : P={base_ab['P']} R={base_ab['R']} "
          f"F1={base_ab['F1']} cobertura={base_ab['cobertura']}%  FP={base_ab['FP']}")

    res = {"run": str(base), "baseline_uniao": base_uniao, "baseline_regra_ab": base_ab,
           "defaults": DEF, "varreduras": {}}

    # 1. piso da 2B (SIM_MINIMA_2B) — so faz sentido com a regra A+B ligada
    lt = [(t, avaliar(linhas, rotulos, regra_ab=True, **{**DEF, "sim_min_2b": t}))
          for t in frange(0.0, 1.0, 0.05)]
    tabela("1) PISO DA 2B (SIM_MINIMA_2B) — regra A+B ligada", "piso", lt, DEF["sim_min_2b"])
    res["varreduras"]["sim_minima_2b"] = [{"valor": v, **m} for v, m in lt]

    # 2. limiar alto da 2A
    lt = [(t, avaliar(linhas, rotulos, regra_ab=False, **{**DEF, "thr_high": t}))
          for t in frange(0.50, 0.95, 0.05)]
    tabela("2) LIMIAR ALTO DA 2A (CORRIGIDO) — regra da uniao", "thr_high", lt, DEF["thr_high"])
    res["varreduras"]["thr_high"] = [{"valor": v, **m} for v, m in lt]

    # 3. limiar baixo da 2A
    lt = [(t, avaliar(linhas, rotulos, regra_ab=False, **{**DEF, "thr_low": t}))
          for t in frange(0.05, 0.50, 0.05)]
    tabela("3) LIMIAR BAIXO DA 2A (NAO_CORRIGIDO) — regra da uniao", "thr_low", lt, DEF["thr_low"])
    res["varreduras"]["thr_low"] = [{"valor": v, **m} for v, m in lt]

    # 4. margem da 2B
    lt = [(t, avaliar(linhas, rotulos, regra_ab=False, **{**DEF, "margin": t}))
          for t in frange(0.01, 0.20, 0.01)]
    tabela("4) MARGEM DA ZONA DE INCERTEZA (2B) — regra da uniao", "margem", lt, DEF["margin"])
    res["varreduras"]["margem_2b"] = [{"valor": v, **m} for v, m in lt]

    dest = out / "sensibilidade_limiares.json"
    json.dump(res, open(dest, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"\n-> {dest}")


if __name__ == "__main__":
    main()
