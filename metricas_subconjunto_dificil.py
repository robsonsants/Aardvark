#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metricas_subconjunto_dificil.py - metrics split by upstream difficulty
==================================================================================
Reports precision/recall/F1/Kappa separately for the upstream that carries the hard
cases and for all the others, under BOTH oracles.

WHY THIS EXISTS
Cross-validation (E2) showed that four of the five upstreams in the published run are
solved perfectly by *any* threshold, while a single upstream - matrix-org/matrix-rust-sdk -
holds 6 of the 7 negatives and 5 of the 5 errors. A pooled metric therefore describes a
population that is mostly trivial, and flatters the method: the effective sample of the
difficult problem is far smaller than the headline n.

Reporting the split is the honest answer to the reviewer's point that the aggregate hides
where the method actually struggles. It also gives the right denominator for deciding how
much a second annotator is worth, and where to spend that annotation effort.

Fully offline: every label is already versioned in the run folder.

Usage:
    python metricas_subconjunto_dificil.py --run resultados_2026-08-31_v2
Output:
    <run>/metricas_subconjunto_dificil.json  (and a readable summary on stdout)
"""
import argparse
import csv
import io
import json
import os
import sys
from collections import defaultdict

if hasattr(sys.stdout, "reconfigure"):                 # console cp1252 no Windows
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

UPSTREAM_DIFICIL = "matrix-org/matrix-rust-sdk"

TRADUZ_HUMANO = {"CORRIGIDO": "CONFIRMED_PATCHED",
                 "VULNERAVEL": "CONFIRMED_VULNERABLE",
                 "NAO_CORRIGIDO": "CONFIRMED_VULNERABLE"}


def metricas(pares):
    """pares: lista de (predito_corrigido: bool, rotulo_positivo: bool)."""
    tp = fp = fn = tn = 0
    for pred, pos in pares:
        if pred and pos:
            tp += 1
        elif pred:
            fp += 1
        elif pos:
            fn += 1
        else:
            tn += 1
    n = tp + fp + fn + tn
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
    kappa = None
    if n:
        p_obs = (tp + tn) / n
        p_aca = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
        kappa = 0.0 if p_aca == 1 else (p_obs - p_aca) / (1 - p_aca)
    return {"n": n, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "P": None if prec is None else round(prec, 4),
            "R": None if rec is None else round(rec, 4),
            "F1": None if f1 is None else round(f1, 4),
            "kappa": None if kappa is None else round(kappa, 4)}


def carregar(run_dir):
    """Devolve (rotulos_auto, rotulos_humano, veredito_uniao, veredito_ab, upstream)."""
    gtm = json.load(open(os.path.join(run_dir, "gt_dissertation_metricas.json"),
                         encoding="utf-8"))
    rot_auto, upstream = {}, {}
    for p in gtm["pares"]:
        up, fork, cve = p["chave"].split("::")
        rot_auto[(fork, cve)] = p["gt"]
        upstream[(fork, cve)] = up

    rot_humano = {}
    csv_path = os.path.join(run_dir, "auditoria_manual_preenchida.csv")
    if os.path.exists(csv_path):
        with io.open(csv_path, encoding="utf-8-sig", newline="") as fh:
            for linha in csv.DictReader(fh, delimiter=";"):
                rotulo = TRADUZ_HUMANO.get((linha.get("veredito_humano") or "").strip())
                if rotulo:
                    chave = (linha["fork"], linha["cve"])
                    rot_humano[chave] = rotulo
                    upstream.setdefault(chave, linha["upstream"])

    def vereditos(pasta):
        caminho = os.path.join(pasta, "dissertation_veredictos.json")
        if not os.path.exists(caminho):
            return {}
        return {(v["fork"], v["cve_id"]): v["status"]
                for v in json.load(open(caminho, encoding="utf-8"))}

    uniao = vereditos(run_dir)
    ab = vereditos(run_dir.rstrip("/\\") + "_regraAB")
    return rot_auto, rot_humano, uniao, ab, upstream


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="resultados_2026-08-31_v2")
    args = ap.parse_args()

    proj = os.path.dirname(os.path.abspath(__file__))
    run_dir = args.run if os.path.isabs(args.run) else os.path.join(proj, args.run)
    rot_auto, rot_humano, uniao, ab, upstream = carregar(run_dir)

    if not ab:
        print("AVISO: %s_regraAB nao encontrado; a Regra A+B fica de fora.\n"
              "       Gere com: python experimento_regra_ab.py --run %s\n"
              % (args.run, args.run))

    classificadores = [("uniao das camadas (pipeline)", uniao),
                       ("Regra A+B", ab)]
    saida = {"run": args.run, "upstream_dificil": UPSTREAM_DIFICIL, "resultados": {}}

    for nome_oraculo, rotulos in (("automatico", rot_auto), ("humano", rot_humano)):
        if not rotulos:
            continue
        for nome_clf, vereditos_clf in classificadores:
            if not vereditos_clf:
                continue
            grupos = defaultdict(list)
            for chave, rotulo in rotulos.items():
                pred = vereditos_clf.get(chave) == "CORRIGIDO"
                pos = rotulo == "CONFIRMED_PATCHED"
                grupo = ("dificil" if upstream.get(chave) == UPSTREAM_DIFICIL
                         else "demais")
                grupos[grupo].append((pred, pos))
                grupos["todos"].append((pred, pos))
            for grupo, pares in grupos.items():
                saida["resultados"].setdefault(nome_oraculo, {}) \
                    .setdefault(nome_clf, {})[grupo] = metricas(pares)

        # baseline trivial (sempre CORRIGIDO), para o mesmo recorte
        grupos = defaultdict(list)
        for chave, rotulo in rotulos.items():
            pos = rotulo == "CONFIRMED_PATCHED"
            grupo = "dificil" if upstream.get(chave) == UPSTREAM_DIFICIL else "demais"
            grupos[grupo].append((True, pos))
            grupos["todos"].append((True, pos))
        for grupo, pares in grupos.items():
            saida["resultados"][nome_oraculo] \
                .setdefault("trivial: sempre CORRIGIDO", {})[grupo] = metricas(pares)

    cab = "%-30s %-8s %3s %3s %3s %3s %3s  %-7s %-7s %-7s %-7s"
    lin = "%-30s %-8s %3s %3d %3d %3d %3d  %-7s %-7s %-7s %-7s"
    for nome_oraculo, por_clf in saida["resultados"].items():
        print("\n" + "=" * 86)
        print("ORACULO: %s" % nome_oraculo.upper())
        print("=" * 86)
        print(cab % ("classificador", "grupo", "n", "TP", "FP", "FN", "TN",
                     "P", "R", "F1", "kappa"))
        for nome_clf, por_grupo in por_clf.items():
            for grupo in ("dificil", "demais", "todos"):
                m = por_grupo.get(grupo)
                if not m:
                    continue
                fmt = lambda v: "-" if v is None else ("%.4f" % v)   # noqa: E731
                print(lin % (nome_clf, grupo, m["n"], m["TP"], m["FP"], m["FN"],
                             m["TN"], fmt(m["P"]), fmt(m["R"]), fmt(m["F1"]),
                             fmt(m["kappa"])))
            print("-" * 86)

    dest = os.path.join(run_dir, "metricas_subconjunto_dificil.json")
    json.dump(saida, open(dest, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n-> %s" % dest)


if __name__ == "__main__":
    main()
