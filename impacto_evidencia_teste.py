#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
impacto_evidencia_teste.py - measuring the cost of the test-evidence bug
==================================================================================
Quantifies, offline, the impact of the deduplication bug that silently discarded the
TEST-file evidence in every run before 2026-08-31_v2.

THE BUG
already_processed() keyed records on (upstream, cve_id, fork, fix_sha) - WITHOUT the
file path. select_patch_files() returns the production file first and the test file
second, so the production record entered the results and the TEST record was then
considered "already processed" and dropped. Consequence: the documented union of
production + test evidence NEVER happened in any earlier run.

WHY MEASURE OFFLINE INSTEAD OF RE-RUNNING
Fork selection is dynamic: re-running would bring a different set of forks and destroy
comparability with the published run. The evidence files (upstream_pre, upstream_post
and each fork's file, test files included) are already archived under
evidencias_dissertacao/, so the discarded records can be recomputed exactly, over the
SAME forks.

Usage:
    python impacto_evidencia_teste.py --run resultados_2026-08-18
"""

import argparse
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

EXT_LANG = pdis.EXT_LANG


def eh_teste(nome_achatado: str) -> bool:
    n = nome_achatado.lower()
    return ("_test_" in n or "_tests_" in n or n.endswith("_test.py")
            or "test" in n.split("_")[-1] or "_spec_" in n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    args = ap.parse_args()
    base = Path(args.run)

    linhas = json.load(open(base / "dissertation_resultados.json", encoding="utf-8"))
    ev_dir = base / "evidencias_dissertacao"

    # metadados por CVE, herdados das linhas de producao ja salvas
    meta = {}
    for r in linhas:
        meta.setdefault(r["cve_id"], r)

    novas = []
    for cve_dir in sorted(ev_dir.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve = cve_dir.name
        m = meta.get(cve)
        if not m:
            continue
        arquivos = [p.name for p in cve_dir.iterdir() if p.is_file()]
        posts = [a for a in arquivos if a.startswith("upstream_post_") and eh_teste(a)]
        for post in posts:
            sufixo = post[len("upstream_post_"):]
            pre = cve_dir / ("upstream_pre_" + sufixo)
            texto_post = (cve_dir / post).read_text(encoding="utf-8", errors="replace")
            texto_pre = (pre.read_text(encoding="utf-8", errors="replace")
                         if pre.exists() else None)
            ext = os.path.splitext(sufixo)[1].lower()
            file_lang = EXT_LANG.get(ext, m["language"])

            for a in arquivos:
                if not a.startswith("fork_") or not a.endswith(sufixo):
                    continue
                # fork_<owner>_<repo>_<caminho achatado>
                miolo = a[len("fork_"):-(len(sufixo) + 1)]
                fork = None
                for r in linhas:
                    o, rp = r["fork"].split("/", 1)
                    if miolo == "%s_%s" % (o, rp):
                        fork = r["fork"]
                        break
                if not fork:
                    continue
                texto_fork = (cve_dir / a).read_text(encoding="utf-8", errors="replace")

                if pdis.layer1_sha(texto_post, texto_fork):
                    status, sim_2a, l2a = "CORRIGIDO", 1.0, "CORRIGIDO"
                    sp = sv = delta = None
                    l2b = "CORRIGIDO"
                else:
                    sim_2a, l2a, _ = pdis.layer2a(texto_post, texto_fork, file_lang)
                    if texto_pre:
                        sp, sv, delta, l2b = pdis.layer2b(
                            texto_pre, texto_post, texto_fork, file_lang)
                    else:
                        sp = sv = delta = None
                        l2b = "NO_PRE_PATCH"
                    status = pdis.decidir_status(l2a, l2b, sim_2a, delta, False)
                novas.append({
                    "upstream": m["upstream"], "category": m["category"],
                    "language": m["language"], "cve_id": cve,
                    "fix_sha": m["fix_sha"], "filepath": "[teste] " + sufixo,
                    "churn": 0, "fork": fork, "fork_pushed": "",
                    "sha_match": status == "CORRIGIDO" and sim_2a == 1.0 and l2b == "CORRIGIDO",
                    "status": status, "sim_2a": sim_2a, "label_2a": l2a,
                    "sim_patch": sp, "sim_vuln": sv, "delta": delta,
                    "label_2b": l2b, "method": "reconstruido", "ts": "",
                })

    print("Linhas de TESTE reconstruidas: %d" % len(novas))
    if not novas:
        return
    por_cve = defaultdict(int)
    for n in novas:
        por_cve[n["cve_id"]] += 1
    for cve in sorted(por_cve):
        print("   %-16s %2d comparacoes" % (cve, por_cve[cve]))

    # ── uniao producao + teste ──────────────────────────────────────────────
    v_antes = pdis.aggregate_verdicts(linhas)
    v_depois = pdis.aggregate_verdicts(linhas + novas)
    a = {(v["fork"], v["cve_id"]): v["status"] for v in v_antes}
    d = {(v["fork"], v["cve_id"]): v["status"] for v in v_depois}
    mudou = [(k, a.get(k), d.get(k)) for k in d if a.get(k) != d.get(k)]

    print("\nVEREDITOS QUE MUDAM COM A UNIAO PRODUCAO+TESTE: %d" % len(mudou))
    for (fork, cve), x, y in sorted(mudou):
        print("   %-40s %-16s %-15s -> %s" % (fork[:40], cve, x, y))

    # ── QD1 / QD2 ───────────────────────────────────────────────────────────
    m_antes = pdis.compute_metrics(v_antes, pdis.compute_coverage(v_antes))
    m_depois = pdis.compute_metrics(v_depois, pdis.compute_coverage(v_depois))
    print("\nQD1 — cobertura media: %.1f%% -> %.1f%%"
          % (m_antes["cobertura_media_pct"], m_depois["cobertura_media_pct"]))

    gt = {}
    for g in json.load(open(base / "gt_dissertation_resultados.json", encoding="utf-8")):
        if g["gt_label"] in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
            prio = {"CONFIRMED_PATCHED": 4, "CONFIRMED_VULNERABLE": 3}
            k = (g["fork"], g["cve"])
            if k not in gt or prio[g["gt_label"]] > prio[gt[k]]:
                gt[k] = g["gt_label"]

    def qd2(mapa):
        tp = fp = fn = tn = 0
        for k, rot in gt.items():
            auto = mapa.get(k, "") == "CORRIGIDO"
            real = rot == "CONFIRMED_PATCHED"
            if auto and real: tp += 1
            elif auto:        fp += 1
            elif real:        fn += 1
            else:             tn += 1
        P = tp / (tp + fp) if tp + fp else None
        R = tp / (tp + fn) if tp + fn else None
        F = 2 * P * R / (P + R) if P and R else None
        return tp, fp, fn, tn, P, R, F

    print("\nQD2 — contra o ground truth ja existente (%d pares conclusivos)" % len(gt))
    print("  %-22s %4s %3s %4s %3s  %-7s %-7s %-7s"
          % ("", "TP", "FP", "FN", "TN", "P", "R", "F1"))
    for nome, mapa in (("so producao (hoje)", a), ("producao + teste", d)):
        tp, fp, fn, tn, P, R, F = qd2(mapa)
        print("  %-22s %4d %3d %4d %3d  %-7s %-7s %-7s"
              % (nome, tp, fp, fn, tn,
                 "—" if P is None else "%.4f" % P,
                 "—" if R is None else "%.4f" % R,
                 "—" if F is None else "%.4f" % F))

    # a mesma coisa sob a Regra A+B
    linhas_ab = []
    for r in linhas + novas:
        n = dict(r)
        if not r["sha_match"] and r["status"] != "FILE_NOT_FOUND":
            n["status"] = pdis.decidir_status(r.get("label_2a"), r.get("label_2b"),
                                              r.get("sim_2a"), r.get("delta"), True)
        linhas_ab.append(n)
    v_ab = pdis.aggregate_verdicts(linhas_ab)
    tp, fp, fn, tn, P, R, F = qd2({(v["fork"], v["cve_id"]): v["status"] for v in v_ab})
    print("  %-22s %4d %3d %4d %3d  %-7s %-7s %-7s"
          % ("prod+teste, Regra A+B", tp, fp, fn, tn,
             "—" if P is None else "%.4f" % P,
             "—" if R is None else "%.4f" % R,
             "—" if F is None else "%.4f" % F))

    json.dump({"n_linhas_teste_reconstruidas": len(novas),
               "vereditos_alterados": [{"fork": k[0], "cve": k[1], "de": x, "para": y}
                                       for k, x, y in mudou]},
              open(base / "impacto_evidencia_teste.json", "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)
    print("\n-> %s" % (base / "impacto_evidencia_teste.json"))


if __name__ == "__main__":
    main()
