# -*- coding: utf-8 -*-
"""
Figura da distribuição das classes de severidade das CVEs verificadas
(pedido do prof. Emanuel, p. 58 da revisão). Offline.

Lê os vereditos do run e cves_enriquecidas.csv, conta as CVEs verificadas por
classe de severidade e grava a figura no mesmo estilo de fig_estados_saida.png.

Uso:
  python gerar_figura_severidade.py
  python gerar_figura_severidade.py --run resultados/matrix/top10 \
         --saida "agora_vai_Dissertação_Robson_MDCC (2)/figuras/fig_severidade_cvss.png"
"""
import argparse
import collections
import csv
import glob
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

ORDEM = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ROTULO = {"LOW": "BAIXA", "MEDIUM": "MÉDIA", "HIGH": "ALTA", "CRITICAL": "CRÍTICA"}
# Uma só matiz, do claro ao escuro: a severidade é ordenada.
TOM = {"LOW": "#e2e2e2", "MEDIUM": "#b4b4b4", "HIGH": "#6e6e6e", "CRITICAL": "#111111"}
FUNDO, TINTA, TINTA2 = "#f3f3f3", "#111111", "#555555"


def fonte(candidatas, padrao):
    nomes = {f.name for f in font_manager.fontManager.ttflist}
    return next((c for c in candidatas if c in nomes), padrao)


def contar(run, enriquecidas):
    ver = json.load(open(os.path.join(run, "dissertation_veredictos.json"), encoding="utf-8"))
    cves = {(v["upstream"], v["cve_id"]) for v in ver}
    sev = {}
    for r in csv.DictReader(open(enriquecidas, encoding="utf-8-sig"), delimiter=";"):
        sev[(r["repo"], r["cve"])] = r["severidade"]
        sev.setdefault(r["cve"], r["severidade"])
    c = collections.Counter()
    for up, cve in cves:
        c[sev.get((up, cve)) or sev.get(cve) or "SEM"] += 1
    return c, len(cves)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="resultados/matrix/top10")
    ap.add_argument("--enriquecidas", default="dados/cves_enriquecidas.csv")
    ap.add_argument("--saida", default=None)
    a = ap.parse_args()

    saida = a.saida
    if not saida:
        pastas = []
        saida = os.path.join(pastas[0] if pastas else ".", "fig_severidade_cvss.png")

    c, n = contar(a.run, a.enriquecidas)
    if c.get("SEM"):
        print("AVISO: %d CVEs sem classe de severidade" % c["SEM"])
    print("CVEs verificadas: %d" % n)
    for k in ORDEM:
        print("  %-8s %3d  %4.1f%%" % (ROTULO[k], c[k], 100.0 * c[k] / n))

    serif = fonte(["Century Schoolbook", "Georgia", "Cambria"], "DejaVu Serif")
    mono = fonte(["DejaVu Sans Mono", "Consolas"], "monospace")

    fig = plt.figure(figsize=(13.86, 4.41), dpi=200, facecolor=FUNDO)
    ax = fig.add_axes([0.025, 0.0, 0.95, 1.0])
    ax.set_facecolor(FUNDO)
    ax.set_xlim(0, n)
    ax.set_ylim(0, 1)
    ax.axis("off")

    y0, alt, folga = 0.17, 0.18, n * 0.0016
    x = 0.0
    for k in ORDEM:
        q = c[k]
        ax.barh(y0 + alt / 2, q - 2 * folga, left=x + folga, height=alt,
                color=TOM[k], edgecolor="none")
        ultimo = k == ORDEM[-1]
        xt = x + q - folga if ultimo else x + folga
        ha = "right" if ultimo else "left"
        ax.text(xt, 0.52, str(q), fontfamily=serif, fontweight="bold", fontsize=40,
                color=TINTA, ha=ha, va="baseline")
        ax.text(xt, 0.41, "%s · %d%%" % (ROTULO[k], round(100.0 * q / n)),
                fontfamily=mono, fontsize=11.5, color=TINTA, ha=ha, va="baseline")
        x += q

    ax.text(folga, 0.07, "CVES VERIFICADAS · N = %d · CLASSE DE SEVERIDADE DO CVSS" % n,
            fontfamily=mono, fontsize=11.5, color=TINTA2, ha="left", va="baseline")

    fig.savefig(saida, dpi=200, facecolor=FUNDO)
    print("-> %s" % saida)


if __name__ == "__main__":
    main()
