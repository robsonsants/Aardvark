"""
gerar_figuras_dissertacao.py — Figures and LaTeX tables for the paper
============================================================================
Reads the results of one run (the --outdir directory of pipeline_dissertation) and
writes into <dir>/figuras/:
  fig1_cobertura_categoria.png   -- RQ1: coverage per category (bar chart)
  fig2_vereditos_categoria.png   -- patched/uncertain verdict mix per category
  fig3_matriz_confusao.png       -- RQ2: confusion matrix (classifier x ground truth)
  tabelas_dissertacao.tex        -- Table RQ1 (coverage) + Table RQ2 (metrics)
  tabelas_dissertacao.md         -- the same tables in Markdown

Usage:  python gerar_figuras_dissertacao.py [--dir resultados_2026-07-04]

Colours: Okabe-Ito palette (colour-blind safe).
"""
import argparse, json, os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ─── Paleta Okabe-Ito (colorblind-safe) ──────────────────────────────────────
C_CORRIGIDO = "#009E73"   # bluish green  → bom
C_INCERTEZA = "#E69F00"   # orange        → atenção
C_VULNER    = "#D55E00"   # vermillion    → sério
C_FNF       = "#999999"   # gray          → sem arquivo
C_MAG       = "#0072B2"   # blue          → magnitude (barra única)
INK, MUTED  = "#222222", "#666666"

CAT_ORDER = ["client", "bridge", "server", "integration", "sdk"]
CAT_LABEL = {"client": "client", "bridge": "bridge", "server": "server",
             "integration": "integration", "sdk": "sdk"}


def _style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#cccccc")
    ax.tick_params(colors=MUTED, labelsize=10)
    ax.title.set_color(INK)


def load(d):
    j = lambda n: json.load(open(os.path.join(d, n), encoding="utf-8"))
    return j("dissertation_cobertura.json"), j("dissertation_metricas.json"), \
           j("dissertation_veredictos.json"), j("gt_dissertation_metricas.json")


def fig1_cobertura(cov, met, out):
    # cobertura média por categoria + projeto e nº forks/CVEs
    proj = {c["category"]: c["upstream"].split("/")[-1] for c in cov}
    nforks = defaultdict(set); ncves = {}
    for c in cov:
        nforks[c["category"]].add(c["fork"]); ncves[c["category"]] = c["n_cves_total"]
    percat = met["por_categoria"]
    cats = [c for c in CAT_ORDER if c in percat]
    vals = [percat[c]["cobertura_media_pct"] for c in cats]

    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    y = range(len(cats))
    ax.barh(y, vals, color=C_MAG, height=0.62, zorder=3)
    ax.set_yticks(list(y))
    ax.set_yticklabels([f"{CAT_LABEL[c]}\n{proj[c]}" for c in cats], fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 108); ax.set_xlabel("Security coverage (% of CVEs patched)", fontsize=10)
    ax.xaxis.grid(True, color="#eeeeee", zorder=0); ax.set_axisbelow(True)
    for i, v in enumerate(vals):
        ax.text(v + 1.5, i, f"{v:.1f}%", va="center", ha="left",
                fontsize=10, color=INK, fontweight="bold")
    m = met["cobertura_media_pct"]
    ax.axvline(m, color=MUTED, ls="--", lw=1, zorder=2)
    ax.text(m, -0.72, f"mean {m:.1f}%", ha="center", va="bottom", fontsize=8.5, color=MUTED)
    ax.set_title("RQ1 - Security coverage per Matrix ecosystem category",
                 fontsize=11, fontweight="bold", pad=14)
    _style(ax)
    fig.tight_layout(); fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


def fig2_vereditos(ver, out):
    comp = defaultdict(lambda: defaultdict(int))
    for v in ver:
        comp[v["category"]][v["status"]] += 1
    cats = [c for c in CAT_ORDER if c in comp]
    order = [("CORRIGIDO", C_CORRIGIDO), ("ZONA_INCERTEZA", C_INCERTEZA),
             ("VULNERAVEL", C_VULNER), ("FILE_NOT_FOUND", C_FNF)]

    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    y = range(len(cats)); left = [0] * len(cats)
    for status, color in order:
        widths = [comp[c].get(status, 0) for c in cats]
        if not any(widths):
            continue
        ax.barh(y, widths, left=left, color=color, height=0.6, zorder=3,
                label=status.replace("_", " ").title(), edgecolor="white", linewidth=1.2)
        for i, (w, l) in enumerate(zip(widths, left)):
            if w > 0:
                ax.text(l + w / 2, i, str(w), va="center", ha="center",
                        fontsize=9, color="white", fontweight="bold")
        left = [l + w for l, w in zip(left, widths)]
    ax.set_yticks(list(y)); ax.set_yticklabels([CAT_LABEL[c] for c in cats], fontsize=10)
    ax.invert_yaxis(); ax.set_xlabel("Number of checks (fork x CVE)", fontsize=10)
    ax.set_title("Verdict composition per category",
                 fontsize=11, fontweight="bold", pad=14)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), frameon=False,
              fontsize=9, ncol=2)
    _style(ax)
    fig.tight_layout(); fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


def fig3_confusao(gt, out):
    tp, fp, fn, tn = gt["TP"], gt["FP"], gt["FN"], gt["TN"]
    M = [[tp, fn], [fp, tn]]           # linhas: GT corrigido / vulnerável
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    vmax = max(tp, fp, fn, tn, 1)
    for r in range(2):
        for c in range(2):
            val = M[r][c]
            inten = val / vmax
            ax.add_patch(plt.Rectangle((c, 1 - r), 1, 1, facecolor=C_MAG,
                                       alpha=0.12 + 0.78 * inten, edgecolor="white", lw=2))
            ax.text(c + 0.5, 1 - r + 0.5, str(val), ha="center", va="center",
                    fontsize=20, fontweight="bold",
                    color="white" if inten > 0.4 else INK)
    ax.set_xlim(0, 2); ax.set_ylim(0, 2)
    ax.set_xticks([0.5, 1.5]); ax.set_xticklabels(["predicts\nPATCHED", "predicts\nnot patched"], fontsize=9)
    ax.set_yticks([1.5, 0.5]); ax.set_yticklabels(["GT:\npatched", "GT:\nvulnerable"], fontsize=9)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("RQ2 - Classifier (Layer 2) vs. ground truth", fontsize=11,
                 fontweight="bold", pad=12)
    cap = (f"Precision {gt['precision']:.2f}   Recall {gt['recall']:.2f}   "
           f"F1 {gt['f1_score']:.2f}\n(0 false positives; the FN are uncertainty-zone "
           f"cases the ground truth confirms as patched)")
    ax.text(1, -0.32, cap, ha="center", va="top", fontsize=8.6, color=MUTED)
    fig.tight_layout(); fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


def tabelas(cov, met, gt, out_tex, out_md):
    proj = {}; lang = {}; nforks = defaultdict(set); ncves = {}
    for c in cov:
        proj[c["category"]] = c["upstream"].split("/")[-1]
        lang[c["category"]] = c["language"]
        nforks[c["category"]].add(c["fork"]); ncves[c["category"]] = c["n_cves_total"]
    cats = [c for c in CAT_ORDER if c in met["por_categoria"]]

    # LaTeX
    tex = [r"% Table RQ1 - coverage per category",
           r"\begin{table}[ht]\centering",
           r"\caption{Security coverage per Matrix ecosystem category.}",
           r"\label{tab:cobertura}",
           r"\begin{tabular}{lllrrr}", r"\hline",
           r"Category & Project & Language & CVEs & Forks & Coverage (\%) \\ \hline"]
    for c in cats:
        tex.append(f"{c} & {proj[c]} & {lang[c]} & {ncves[c]} & {len(nforks[c])} & "
                   f"{met['por_categoria'][c]['cobertura_media_pct']:.1f} \\\\")
    tex += [r"\hline",
            f"\\textbf{{Mean}} & & & & & \\textbf{{{met['cobertura_media_pct']:.1f}}} \\\\",
            r"\hline", r"\end{tabular}", r"\end{table}", "",
            r"% Table RQ2 - reliability metrics",
            r"\begin{table}[ht]\centering",
            r"\caption{Reliability of Layer 2 (AST) against the ground truth.}",
            r"\label{tab:metricas}", r"\begin{tabular}{lr}", r"\hline",
            r"Metric & Value \\ \hline",
            f"True positives (TP) & {gt['TP']} \\\\",
            f"False positives (FP) & {gt['FP']} \\\\",
            f"False negatives (FN) & {gt['FN']} \\\\",
            f"True negatives (TN) & {gt['TN']} \\\\",
            f"Precision & {gt['precision']:.3f} \\\\",
            f"Recall & {gt['recall']:.3f} \\\\",
            f"F1-score & {gt['f1_score']:.3f} \\\\",
            f"Accuracy & {gt['accuracy']:.3f} \\\\",
            f"Cohen\'s Kappa & {gt['kappa_cohen']:.3f} \\\\",
            r"\hline", r"\end{tabular}", r"\end{table}"]
    open(out_tex, "w", encoding="utf-8").write("\n".join(tex) + "\n")

    md = ["### RQ1 - Coverage per category", "",
          "| Category | Project | Language | CVEs | Forks | Coverage (%) |",
          "|---|---|---|---|---|---|"]
    for c in cats:
        md.append(f"| {c} | {proj[c]} | {lang[c]} | {ncves[c]} | {len(nforks[c])} | "
                  f"{met['por_categoria'][c]['cobertura_media_pct']:.1f} |")
    md.append(f"| **Mean** | | | | | **{met['cobertura_media_pct']:.1f}** |")
    md += ["", "### RQ2 - Reliability (Layer 2 vs. ground truth)", "",
           "| Metric | Value |", "|---|---|",
           f"| TP / FP / FN / TN | {gt['TP']} / {gt['FP']} / {gt['FN']} / {gt['TN']} |",
           f"| Precision | {gt['precision']:.3f} |",
           f"| Recall | {gt['recall']:.3f} |",
           f"| F1-score | {gt['f1_score']:.3f} |",
           f"| Accuracy | {gt['accuracy']:.3f} |",
           f"| Cohen's Kappa | {gt['kappa_cohen']:.3f} |"]
    open(out_md, "w", encoding="utf-8").write("\n".join(md) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="resultados_2026-07-04")
    args = ap.parse_args()
    cov, met, ver, gt = load(args.dir)
    figdir = os.path.join(args.dir, "figuras"); os.makedirs(figdir, exist_ok=True)
    fig1_cobertura(cov, met, os.path.join(figdir, "fig1_cobertura_categoria.png"))
    fig2_vereditos(ver, os.path.join(figdir, "fig2_vereditos_categoria.png"))
    fig3_confusao(gt, os.path.join(figdir, "fig3_matriz_confusao.png"))
    tabelas(cov, met, gt, os.path.join(figdir, "tabelas_dissertacao.tex"),
            os.path.join(figdir, "tabelas_dissertacao.md"))
    print("Gerado em", figdir + ":")
    for f in sorted(os.listdir(figdir)):
        print("  ", f)


if __name__ == "__main__":
    main()
