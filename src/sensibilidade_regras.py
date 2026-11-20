#!/usr/bin/env python3
"""
Funções de apoio à avaliação: re-derivam o veredito de cada linha crua com limiares
dados, sem rede e sem reprocessar a árvore sintática. Usadas por avaliacao_gabaritos.py
(classificadores e análise de sensibilidade do limiar superior da Camada 2A).

Nenhum limiar muda uma medida: sim_2a, sim_patch, sim_vuln e delta já estão gravados nas
linhas cruas da execução. Os limiares só mudam como esses números viram rótulo (2A/2B) e
como os rótulos viram veredito.
"""
import os, sys

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
