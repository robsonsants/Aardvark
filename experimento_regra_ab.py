#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
experimento_regra_ab.py - controlled experiment: the A+B rule vs the union rule
==================================================================================
Re-derives, OFFLINE, what the A+B decision rule would have produced over an existing
run, and reports the differential against the current methodology (the union rule).

WHY RE-DERIVE INSTEAD OF RE-RUNNING
The A+B rule changes no measurement: sim_2a, sim_patch, sim_vuln and delta are already
computed and stored in the raw records of the base run. The rule only changes how those
numbers become a verdict. Re-running Phase 2 against the API would bring a DIFFERENT set
of forks (selection is dynamic) and destroy comparability - the differential would no
longer isolate the rule. Here the records are exactly the same; only the status moves.
No network, no token.

RQ1 is re-derived the same way: ground-truth labels (CONFIRMED_PATCHED /
CONFIRMED_VULNERABLE) do not depend on the rule, so the pairs in
gt_dissertation_resultados.json are reused and simply crossed with the new verdict.

Usage:
    python experimento_regra_ab.py --run resultados_2026-08-31_v2
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_dissertation as pdis  # noqa: E402


def qd2(rotulos_gt, veredito_por_par):
    """Precisao/recall/F1 do veredito automatico contra o ground truth."""
    tp = fp = fn = tn = 0
    for par, rot in rotulos_gt.items():
        auto = veredito_por_par.get(par, "") == "CORRIGIDO"
        real = rot == "CONFIRMED_PATCHED"
        if auto and real:
            tp += 1
        elif auto:
            fp += 1
        elif real:
            fn += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
    total = tp + fp + fn + tn
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "n_pares": total,
            "precision": None if prec is None else round(prec, 4),
            "recall": None if rec is None else round(rec, 4),
            "f1": None if f1 is None else round(f1, 4),
            "accuracy": round((tp + tn) / total, 4) if total else None}


def vereditos_por_par(verdicts):
    return {(v["fork"], v["cve_id"]): v["status"] for v in verdicts}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="pasta datada do run base")
    ap.add_argument("--outdir", default=None,
                    help="pasta de saida (padrao: <run>_regraAB)")
    args = ap.parse_args()

    base = Path(args.run)
    out = Path(args.outdir) if args.outdir else Path(str(base).rstrip("/\\") + "_regraAB")
    out.mkdir(parents=True, exist_ok=True)

    linhas_base = json.load(open(base / "dissertation_resultados.json", encoding="utf-8"))
    print(f"Run base : {base}  ({len(linhas_base)} linhas cruas)")

    # ── re-decidir o status de cada linha com a regra A+B ────────────────────
    linhas_ab, mudancas = [], []
    for r in linhas_base:
        novo = dict(r)
        if r["sha_match"] or r["status"] == "FILE_NOT_FOUND":
            pass                      # camada 1 e ausencia de arquivo nao mudam
        else:
            st = pdis.decidir_status(r.get("label_2a"), r.get("label_2b"),
                                     r.get("sim_2a"), r.get("delta"), regra_ab=True)
            if st != r["status"]:
                mudancas.append({
                    "fork": r["fork"], "cve": r["cve_id"], "arquivo": r["filepath"],
                    "de": r["status"], "para": st,
                    "sim_2a": r.get("sim_2a"), "delta": r.get("delta"),
                    "label_2a": r.get("label_2a"), "label_2b": r.get("label_2b"),
                })
            novo["status"] = st
        linhas_ab.append(novo)

    verdicts_ab = pdis.aggregate_verdicts(linhas_ab)
    coverage_ab = pdis.compute_coverage(verdicts_ab)
    metrics_ab = pdis.compute_metrics(verdicts_ab, coverage_ab)

    cwd = os.getcwd()
    os.chdir(out)
    try:
        pdis.save_results(linhas_ab, verdicts_ab, coverage_ab, metrics_ab)
    finally:
        os.chdir(cwd)

    # ── QD1: diferencial ────────────────────────────────────────────────────
    metrics_base = json.load(open(base / "dissertation_metricas.json", encoding="utf-8"))

    # ── QD2: reaproveita os rotulos do ground truth ─────────────────────────
    gt_path = base / "gt_dissertation_resultados.json"
    linha_qd2 = None
    if gt_path.exists():
        rotulos = {}
        for g in json.load(open(gt_path, encoding="utf-8")):
            if g["gt_label"] in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
                rotulos[(g["fork"], g["cve"])] = g["gt_label"]
        verdicts_base = json.load(open(base / "dissertation_veredictos.json",
                                       encoding="utf-8"))
        m_base = qd2(rotulos, vereditos_por_par(verdicts_base))
        m_ab = qd2(rotulos, vereditos_por_par(verdicts_ab))
        linha_qd2 = {"base": m_base, "regra_ab": m_ab, "n_rotulos_gt": len(rotulos)}
        json.dump(linha_qd2, open(out / "gt_regra_ab_metricas.json", "w",
                                  encoding="utf-8"), indent=2, ensure_ascii=False)

    diff = {
        "run_base": str(base), "run_regra_ab": str(out),
        "sim_minima_2b": pdis.SIM_MINIMA_2B,
        "n_linhas": len(linhas_base),
        "n_linhas_alteradas": len(mudancas),
        "qd1_base": metrics_base, "qd1_regra_ab": metrics_ab,
        "qd2": linha_qd2,
        "linhas_alteradas": mudancas,
    }
    json.dump(diff, open(out / "DIFERENCIAL_regra_ab.json", "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)

    # ── relatorio ───────────────────────────────────────────────────────────
    print("\n" + "=" * 66)
    print("DIFERENCIAL — regra da uniao (base) vs regra A+B")
    print("=" * 66)
    print(f"Linhas alteradas: {len(mudancas)} de {len(linhas_base)}")
    for m in mudancas:
        print("  %-32s %-16s %-26s %s -> %s  (2A=%s d=%s)" % (
            m["fork"][:32], m["cve"], os.path.basename(m["arquivo"])[:26],
            m["de"], m["para"], m["sim_2a"], m["delta"]))

    print("\nQD1 — cobertura")
    print("  %-22s %8s %8s" % ("", "base", "regra A+B"))
    print("  %-22s %8s %8s" % ("cobertura media %",
                               metrics_base["cobertura_media_pct"],
                               metrics_ab["cobertura_media_pct"]))
    for campo in ("n_corrigidas", "n_vulneraveis", "n_zona_incerteza", "n_verificacoes"):
        print("  %-22s %8s %8s" % (campo, metrics_base[campo], metrics_ab[campo]))
    print("\n  por categoria (cobertura media %)")
    for cat in sorted(metrics_ab["por_categoria"]):
        b = metrics_base["por_categoria"].get(cat, {}).get("cobertura_media_pct", "-")
        a = metrics_ab["por_categoria"][cat]["cobertura_media_pct"]
        print("    %-14s %8s %8s" % (cat, b, a))

    if linha_qd2:
        print(f"\nQD2 — contra ground truth ({linha_qd2['n_rotulos_gt']} pares conclusivos)")
        print("  %-10s %4s %3s %4s %3s  %-7s %-7s %-7s" %
              ("", "TP", "FP", "FN", "TN", "P", "R", "F1"))
        for nome, m in (("base", linha_qd2["base"]), ("regra A+B", linha_qd2["regra_ab"])):
            print("  %-10s %4d %3d %4d %3d  %-7s %-7s %-7s" %
                  (nome, m["TP"], m["FP"], m["FN"], m["TN"],
                   m["precision"], m["recall"], m["f1"]))

    print(f"\n-> {out}")


if __name__ == "__main__":
    main()
