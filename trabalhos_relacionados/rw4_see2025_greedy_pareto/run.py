# -*- coding: utf-8 -*-
"""
rw4 — See et al. (2025), "Enhancing Binary Code Similarity Analysis for Software
      Updates: A Contextual Diffing Framework" (ACM AsiaCCS).

REPRODUCED METHOD
  GREEDY combinatorial optimisation (greedy set cover) for the MACRO diagnosis of the
  fork chain, analogous to the greedy strategy adopted by See et al. We build the
  fork x (upstream, CVE) matrix, where a cell is 1 when the fork is patched (final
  verdict, aggregated by union). The algorithm iteratively picks the fork covering the
  largest number of still-uncovered vulnerabilities, yielding the ecosystem's PARETO
  CURVE: "with K forks you cover X% of the vulnerabilities".

SIGNAL USED: status (final verdict per fork x CVE pair).
OUTPUT: cumulative curve (K forks -> % coverage) and the network's coverage ceiling.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import load_rows, agg_by_key, dump_dated

agg = agg_by_key(load_rows())

# Universo = todas as vulnerabilidades distintas (upstream, CVE) observadas.
universe = sorted({(v["upstream"], v["cve_id"]) for v in agg.values()})
# Cobertura de cada fork: pares (upstream, CVE) que ele CORRIGE.
fork_cov = {}
for v in agg.values():
    if v["status"] == "CORRIGIDO":
        fork_cov.setdefault(v["fork"], set()).add((v["upstream"], v["cve_id"]))

resolvable = set().union(*fork_cov.values()) if fork_cov else set()

covered, curve, remaining = set(), [], dict(fork_cov)
while remaining:
    best = max(remaining, key=lambda f: len(remaining[f] - covered))
    gain = len(remaining[best] - covered)
    if gain == 0:
        break
    covered |= remaining[best]
    curve.append({
        "k": len(curve) + 1, "fork": best, "ganho": gain,
        "acumulado": len(covered),
        "cobertura_universo_pct": round(100 * len(covered) / len(universe), 1),
        "cobertura_resolvivel_pct": round(100 * len(covered) / len(resolvable), 1) if resolvable else 0.0,
    })
    del remaining[best]

out = {
    "trabalho": "See et al. (2025) — otimização gulosa / Curva de Pareto (diagnóstico macro)",
    "papel_na_proposta": "Matriz de cobertura + set-cover guloso (§3.4, §4.5)",
    "n_vulnerabilidades_universo": len(universe),
    "n_vulnerabilidades_resolviveis": len(resolvable),
    "n_forks_com_alguma_correcao": len(fork_cov),
    "teto_cobertura_pct": round(100 * len(resolvable) / len(universe), 1) if universe else 0.0,
    "forks_para_o_teto": len(curve),
    "curva_pareto": curve,
}
p = dump_dated("rw4_see2025_greedy_pareto.json", out)
print("=== rw4 See et al. 2025 (guloso / Pareto) ===")
print(f"Vulnerabilidades (upstream,CVE) no universo : {out['n_vulnerabilidades_universo']}")
print(f"Resolvíveis por >=1 fork (teto)             : {out['n_vulnerabilidades_resolviveis']} "
      f"({out['teto_cobertura_pct']}%)")
print(f"Forks necessários p/ atingir o teto         : {out['forks_para_o_teto']}")
print("Curva de Pareto (K -> % universo):")
for e in curve:
    print(f"  K={e['k']:>2}  +{e['ganho']:>2}  acum={e['acumulado']:>2}  "
          f"{e['cobertura_universo_pct']:>5}% universo | {e['cobertura_resolvivel_pct']:>5}% resolvível  <- {e['fork']}")
print(f"-> {p}")
