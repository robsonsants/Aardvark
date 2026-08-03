# -*- coding: utf-8 -*-
"""
Renders the target (to-be) PROCESS FLOW as an image (PNG + SVG), from the flowchart
described in RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md.

Output: figuras/diagrama_processo_to_be.png  (300 dpi, for slides/print)
        figuras/diagrama_processo_to_be.svg  (vector, for the paper)
"""
import os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figuras")
os.makedirs(OUT, exist_ok=True)

# paleta sóbria e segura para daltonismo (cor nunca é o único sinal: há rótulo de texto)
INK = "#1b2330"
C_MINE_F, C_MINE_E = "#e2ebf8", "#2f5c9e"     # Fase 1 (mineração) — azul
C_VER_F,  C_VER_E = "#dcefe7", "#1f7a5c"      # Fase 2 (verificação) — verde-azulado
C_LAY_F,  C_LAY_E = "#eef1f5", "#7a8699"      # camadas — cinza
C_OK_F,   C_OK_E = "#d8eee0", "#2e7d46"       # CORRIGIDO
C_ZI_F,   C_ZI_E = "#fbeecf", "#b8860b"       # ZONA_INCERTEZA
C_VU_F,   C_VU_E = "#f6dcdc", "#b23a3a"       # VULNERAVEL

fig, ax = plt.subplots(figsize=(11.5, 15.5))
ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")


def box(cx, cy, w, h, text, fill, edge, fs=11, bold=False, tcol=None):
    x0, y0 = cx - w / 2, cy - h / 2
    p = FancyBboxPatch((x0, y0), w, h,
                       boxstyle="round,pad=0.15,rounding_size=1.4",
                       linewidth=1.8, facecolor=fill, edgecolor=edge, zorder=2)
    ax.add_patch(p)
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs, color=tcol or INK,
            fontweight="bold" if bold else "normal", zorder=3, linespacing=1.35)


def arrow(x1, y1, x2, y2, rad=0.0, color=INK, lw=1.7):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                 mutation_scale=16, lw=lw, color=color, shrinkA=3, shrinkB=3,
                 connectionstyle=f"arc3,rad={rad}", zorder=1))


def band(cy0, cy1, label, color):
    ax.add_patch(plt.Rectangle((1.5, cy1), 4.2, cy0 - cy1, facecolor=color,
                 edgecolor="none", alpha=0.85, zorder=0))
    ax.text(3.6, (cy0 + cy1) / 2, label, rotation=90, ha="center", va="center",
            fontsize=12, fontweight="bold", color="white", zorder=1)


# faixas de fase (fronteira entre a etapa 3 e a 4)
band(99, 75.5, "FASE 1 · Mineração do upstream", C_MINE_E)
band(74.5, 4, "FASE 2 · Verificação nos forks", C_VER_E)

W, H = 62, 5.2
CX = 54
# Fase 1
box(CX, 95, W, H, "1 · UPSTREAM — CPE → CVEs\n(NVD + GHSA, com retry/backoff)", C_MINE_F, C_MINE_E, bold=True)
box(CX, 87, W, H, "2 · Localizar commit(s) de correção\n(referências do NVD/GHSA → fix SHA)", C_MINE_F, C_MINE_E)
box(CX, 79, W, H, "3 · Extrair função PRÉ / PÓS-fix\n(tree-sitter · py/rust/kotlin/swift/ts/go)", C_MINE_F, C_MINE_E)
# Fase 2
box(CX, 71, W, H, "4 · Indexar forks DIVERGENTES ativos\n(ahead_by > 0 no compare · janela 730 d · top-3)", C_VER_F, C_VER_E, bold=True)
box(CX, 63, W, H, "5 · QUERY = trecho vulnerável  →  RANKING semântico\n(embeddings UniXcoder, mean-pool + cosseno)", C_VER_F, C_VER_E)

# 6 · camadas
box(CX, 55, W, 4.4, "6 · VERIFICAÇÃO EM CAMADAS (sinais independentes)", C_VER_F, C_VER_E, bold=True)
lay_y = 48.5
lw_ = 21
for i, (cx, t) in enumerate([
        (18, "C1\nHash SHA\n(idêntico)"),
        (41, "C2A\nAST norm.\n+ Levenshtein"),
        (64, "C2B\ndupla ref.\n|δ| ≤ 0,05"),
        (87, "Embeddings\nsemânticos\n(near-miss)")]):
    box(cx, lay_y, lw_, 6.8, t, C_LAY_F, C_LAY_E, fs=9.5)
    arrow(CX, 55 - 2.2, cx, lay_y + 3.4, rad=0.0 if abs(cx - CX) < 2 else (0.12 if cx > CX else -0.12))

# 7 · combinador
box(CX, 39, W, H, "7 · COMBINADOR — união dos sinais\n(CORRIGIDO se QUALQUER camada confirma)", C_VER_F, C_VER_E, bold=True)
for cx in (18, 41, 64, 87):
    arrow(cx, lay_y - 3.4, CX, 39 + 2.6, rad=0.0 if abs(cx - CX) < 2 else (-0.12 if cx > CX else 0.12))

# 8 · decisão em 3 vias
box(CX, 31, 30, 4.6, "DECISÃO", "#ffffff", INK, bold=True)
arrow(CX, 39 - 2.6, CX, 31 + 2.3)
box(19, 22, 25, 5.6, "CORRIGIDO\n(patch presente)", C_OK_F, C_OK_E, fs=10, bold=True, tcol=C_OK_E)
box(54, 22, 25, 5.6, "ZONA_INCERTEZA\n(borda → escala)", C_ZI_F, C_ZI_E, fs=10, bold=True, tcol="#7a5a06")
box(81, 22, 25, 5.6, "VULNERAVEL\n(patch ausente)", C_VU_F, C_VU_E, fs=10, bold=True, tcol=C_VU_E)
arrow(CX - 6, 31 - 2.3, 19, 22 + 2.8, rad=0.15, color=C_OK_E)
arrow(CX, 31 - 2.3, 54, 22 + 2.8, color=C_ZI_E)
arrow(CX + 6, 31 - 2.3, 81, 22 + 2.8, rad=-0.15, color=C_VU_E)

# auditoria humana (a partir da zona de incerteza)
box(54, 13.5, 30, 4.6, "AUDITORIA HUMANA\n(banca §4 · ground truth)", "#ffffff", C_ZI_E, fs=9.5)
arrow(54, 22 - 2.8, 54, 13.5 + 2.3, color=C_ZI_E)

# 9 · resultados / questões de pesquisa
box(CX, 6, W, 5.4,
    "QP1 · confiabilidade:  Precisão / Recall / F1 / κ\n"
    "QP2 · propagação:  cobertura, technical-lag, Pareto (set-cover)",
    "#eaf0e9", C_VER_E, fs=10, bold=True)
arrow(19, 22 - 2.8, 40, 6 + 2.7, rad=-0.1, color=C_OK_E)      # CORRIGIDO → resultados
arrow(81, 22 - 2.8, 68, 6 + 2.7, rad=0.1, color=C_VU_E)       # VULNERAVEL → resultados
arrow(54, 13.5 - 2.3, 54, 6 + 2.7, color=C_ZI_E)             # auditoria → resultados

ax.text(54, 99.3, "Verificação de propagação de patches de segurança em forks divergentes — fluxo do processo (to-be)",
        ha="center", va="top", fontsize=13.5, fontweight="bold", color=INK)

plt.tight_layout(pad=0.5)
png = os.path.join(OUT, "diagrama_processo_to_be.png")
svg = os.path.join(OUT, "diagrama_processo_to_be.svg")
fig.savefig(png, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg, bbox_inches="tight", facecolor="white")
print("-> " + png)
print("-> " + svg)
