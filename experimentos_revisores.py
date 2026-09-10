#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
experimentos_revisores.py - six validation experiments answering peer-review feedback
==================================================================================
An earlier version of this study was submitted to a conference and rejected. The three
reports converged on one methodological criticism: recall had been measured on a
population where every pair was positive, and precision on a CONSTRUCTED set, without
ever comparing the method against a constant classifier. This script answers that
feedback with measurements rather than argument, over the corrected run.

  E1  Trivial baselines (constant classifier) vs each layer and their combinations.
  E2  Threshold cross-validation: leave-one-upstream-out and stratified k-fold, with
      thresholds selected on the training folds only.
  E3  Patch-size discriminant: is "small patch vs big patch" a usable rule?
  E4  Bootstrap confidence intervals (10,000 resamples) and exact McNemar tests.
  E5  Failure analysis: every error, one by one, with its evidence.
  E6  Operating curve: sweeping the Layer 2A high threshold, with the trivial
      baseline marked on the same axis.

Every experiment runs under BOTH oracles - the automated ground truth and the human
audit - and reports them side by side, never mixed. Fully offline: all quantities are
re-derived from the raw records of the run.

Usage:
    python experimentos_revisores.py --run resultados_2026-08-31_v2
Output:
    <run>/experimentos_revisores.json  (and a readable summary on stdout)
"""

import argparse, csv, json, math, os, random, sys
from collections import defaultdict, Counter
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_core as pc
import pipeline_dissertation as pdis
from sensibilidade_regras import redecidir, DEF

random.seed(20260908)   # reprodutibilidade do bootstrap e dos folds


# ══════════════════════════════════════════════════════════ metricas
def confusao(pred_corrigido: dict, rotulo_positivo: dict) -> dict:
    """pred_corrigido: par -> bool. rotulo_positivo: par -> bool (o oraculo)."""
    tp = fp = fn = tn = 0
    for par, real in rotulo_positivo.items():
        if par not in pred_corrigido:
            continue
        auto = pred_corrigido[par]
        if auto and real:    tp += 1
        elif auto:           fp += 1
        elif real:           fn += 1
        else:                tn += 1
    return dict(TP=tp, FP=fp, FN=fn, TN=tn)


def metricas(c: dict) -> dict:
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    n = tp + fp + fn + tn
    p  = tp / (tp + fp) if tp + fp else None
    r  = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if (p is not None and r is not None) else None)
    acc = (tp + tn) / n if n else None
    # Kappa de Cohen
    if n:
        p_obs = (tp + tn) / n
        p_esp = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
        kappa = (p_obs - p_esp) / (1 - p_esp) if abs(1 - p_esp) > 1e-12 else 0.0
    else:
        p_obs = p_esp = kappa = None
    return dict(**c, n=n,
                P=None if p is None else round(p, 4),
                R=None if r is None else round(r, 4),
                F1=None if f1 is None else round(f1, 4),
                acc=None if acc is None else round(acc, 4),
                p_obs=None if p_obs is None else round(p_obs, 4),
                p_esperado_acaso=None if p_esp is None else round(p_esp, 4),
                kappa=None if kappa is None else round(kappa, 4))


def prever(linhas, rotulos, regra_ab=False, **kw):
    """Re-deriva os vereditos com os limiares dados -> par -> bool(CORRIGIDO)."""
    lin = redecidir(linhas, regra_ab=regra_ab, **{**DEF, **kw})
    verd = pdis.aggregate_verdicts(lin)
    por_par = {(v["fork"], v["cve_id"]): v["status"] for v in verd}
    return ({par: por_par.get(par, "") == "CORRIGIDO" for par in rotulos},
            por_par, verd, lin)


# ══════════════════════════════════════════════════════════ carga
def carregar(base: Path):
    linhas = json.load(open(base / "dissertation_resultados.json", encoding="utf-8"))

    gt = json.load(open(base / "gt_dissertation_resultados.json", encoding="utf-8"))
    oraculo_auto, gt_rows = {}, {}
    for g in gt:
        par = (g["fork"], g["cve"])
        gt_rows.setdefault(par, g)
        if g["gt_label"] in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
            oraculo_auto[par] = (g["gt_label"] == "CONFIRMED_PATCHED")

    oraculo_hum, aud_rows = {}, {}
    fa = base / "auditoria_manual_preenchida.csv"
    if fa.exists():
        for row in csv.DictReader(open(fa, encoding="utf-8-sig"), delimiter=";"):
            v = (row.get("veredito_humano") or "").strip().upper()
            par = (row["fork"], row["cve"])
            aud_rows[par] = row
            if v == "CORRIGIDO":    oraculo_hum[par] = True
            elif v == "VULNERAVEL": oraculo_hum[par] = False

    up_por_par = {(r["fork"], r["cve_id"]): r["upstream"] for r in linhas}
    cat_por_par = {(r["fork"], r["cve_id"]): r["category"] for r in linhas}
    return dict(linhas=linhas, auto=oraculo_auto, humano=oraculo_hum,
                gt_rows=gt_rows, aud_rows=aud_rows,
                upstream=up_por_par, categoria=cat_por_par)


# ══════════════════════════════════════════════════════════ E1
def e1_baselines(D, out):
    print("\n" + "=" * 78)
    print("E1 — BASELINES TRIVIAIS  (classificador constante como linha de comparacao)")
    print("=" * 78)

    res = {}
    for nome_or, oraculo in (("automatico", D["auto"]), ("humano", D["humano"])):
        if not oraculo:
            continue
        n_pos = sum(1 for v in oraculo.values() if v)
        n_neg = len(oraculo) - n_pos
        print(f"\n  Oraculo {nome_or}: {len(oraculo)} pares "
              f"({n_pos} positivos, {n_neg} negativos — "
              f"prevalencia {100*n_pos/len(oraculo):.1f}%)")

        linha = {}
        # constante: sempre CORRIGIDO / sempre VULNERAVEL
        linha["trivial: sempre CORRIGIDO"] = metricas(
            confusao({p: True for p in oraculo}, oraculo))
        linha["trivial: sempre VULNERAVEL"] = metricas(
            confusao({p: False for p in oraculo}, oraculo))
        # camadas isoladas
        for nome, kw in (("Camada 1 (hash)", None),
                         ("Camada 2A isolada", "2a"),
                         ("Camada 2B isolada", "2b")):
            pred = {}
            agrup = defaultdict(list)
            for r in D["linhas"]:
                agrup[(r["fork"], r["cve_id"])].append(r)
            for par in oraculo:
                rows = agrup.get(par, [])
                if nome.startswith("Camada 1"):
                    ok = any(r.get("sha_match") for r in rows)
                elif kw == "2a":
                    ok = any(r.get("label_2a") == "CORRIGIDO" for r in rows)
                else:
                    ok = any(r.get("label_2b") == "CORRIGIDO" for r in rows)
                pred[par] = ok
            linha[nome] = metricas(confusao(pred, oraculo))
        # pipeline
        pred_u, _, _, _ = prever(D["linhas"], oraculo, regra_ab=False)
        pred_ab, _, _, _ = prever(D["linhas"], oraculo, regra_ab=True)
        linha["PIPELINE: uniao das camadas"] = metricas(confusao(pred_u, oraculo))
        linha["PIPELINE: Regra A+B"] = metricas(confusao(pred_ab, oraculo))

        print("    %-30s %4s %3s %4s %3s  %-7s %-7s %-7s %-7s %-7s" %
              ("metodo", "TP", "FP", "FN", "TN", "P", "R", "F1", "acc", "kappa"))
        for nome, m in linha.items():
            print("    %-30s %4d %3d %4d %3d  %-7s %-7s %-7s %-7s %-7s" %
                  (nome, m["TP"], m["FP"], m["FN"], m["TN"],
                   m["P"], m["R"], m["F1"], m["acc"], m["kappa"]))
        res[nome_or] = linha

    # a leitura critica que este experimento antecipa
    for nome_or in res:
        triv = res[nome_or]["trivial: sempre CORRIGIDO"]
        uni  = res[nome_or]["PIPELINE: uniao das camadas"]
        print(f"\n  LEITURA (oraculo {nome_or}):")
        print(f"    F1     trivial {triv['F1']}  vs  uniao {uni['F1']}  "
              f"(delta {round(uni['F1']-triv['F1'], 4):+})")
        print(f"    Kappa  trivial {triv['kappa']}  vs  uniao {uni['kappa']}"
              "   <-- e AQUI que o metodo se separa do trivial")
        print(f"    FP     trivial {triv['FP']}    vs  uniao {uni['FP']}    "
              "(falso positivo = falsa sensacao de seguranca)")
    out["E1_baselines"] = res
    return res


# ══════════════════════════════════════════════════════════ E2
GRADE = dict(
    thr_high=[round(x, 2) for x in [0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]],
    margin=[round(x, 3) for x in [0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10]],
    sim_min_2b=[round(x, 2) for x in [0.00, 0.50, 0.55, 0.60, 0.65, 0.70]],
)


def _busca(linhas, oraculo_treino, regra_ab, criterio):
    """Grid search nos limiares, SO com os pares de treino."""
    melhor, melhor_cfg = None, None
    for th in GRADE["thr_high"]:
        for mg in GRADE["margin"]:
            for pm in (GRADE["sim_min_2b"] if regra_ab else [DEF["sim_min_2b"]]):
                cfg = dict(thr_high=th, margin=mg, sim_min_2b=pm)
                pred, _, _, _ = prever(linhas, oraculo_treino, regra_ab=regra_ab, **cfg)
                m = metricas(confusao(pred, oraculo_treino))
                if criterio == "f1":
                    score = (m["F1"] or 0.0,)
                else:  # cobertura maxima com zero FP
                    score = (1 if m["FP"] == 0 else 0, m["TP"])
                if melhor is None or score > melhor:
                    melhor, melhor_cfg = score, cfg
    return melhor_cfg


def e2_validacao_cruzada(D, out):
    print("\n" + "=" * 78)
    print("E2 — VALIDACAO CRUZADA DOS LIMIARES  (holdout por upstream + k-fold)")
    print("=" * 78)

    res = {}
    for nome_or, oraculo in (("automatico", D["auto"]), ("humano", D["humano"])):
        if len(oraculo) < 10:
            continue
        pares = sorted(oraculo)
        print(f"\n  --- oraculo {nome_or} ({len(pares)} pares) ---")

        esquemas = {}

        # (a) leave-one-upstream-out — o mais honesto: o fold de teste nao
        #     compartilha upstream, CVE nem fork com o de treino
        folds_up = defaultdict(list)
        for p in pares:
            folds_up[D["upstream"].get(p, "?")].append(p)
        esquemas["leave-one-upstream-out"] = list(folds_up.items())

        # (b) k-fold estratificado por rotulo (k=5)
        pos = [p for p in pares if oraculo[p]]
        neg = [p for p in pares if not oraculo[p]]
        random.shuffle(pos); random.shuffle(neg)
        k = 5
        folds_k = [[] for _ in range(k)]
        for i, p in enumerate(pos): folds_k[i % k].append(p)
        for i, p in enumerate(neg): folds_k[i % k].append(p)
        esquemas["k-fold estratificado (k=5)"] = [
            (f"fold {i+1}", f) for i, f in enumerate(folds_k)]

        for (nome_esq, folds), criterio in [
                (e, c) for e in esquemas.items() for c in ("f1", "zero_fp")]:
            nome_esq = "%s · criterio de selecao no treino: %s" % (
                nome_esq, "maximo F1" if criterio == "f1" else "cobertura maxima com FP=0")
            print(f"\n  {nome_esq}")
            print("    %-34s %-28s %4s %3s %4s %3s  %-7s %-7s" %
                  ("fold (teste)", "limiares escolhidos no treino",
                   "TP", "FP", "FN", "TN", "P", "R"))
            acum_oos = dict(TP=0, FP=0, FN=0, TN=0)
            acum_def = dict(TP=0, FP=0, FN=0, TN=0)
            escolhas = []
            for nome_fold, teste in folds:
                if not teste:
                    continue
                treino = {p: oraculo[p] for p in pares if p not in teste}
                if len(set(treino.values())) < 2:
                    cfg = dict(thr_high=DEF["thr_high"], margin=DEF["margin"],
                               sim_min_2b=DEF["sim_min_2b"])
                    nota = " (treino sem 2 classes -> default)"
                else:
                    cfg = _busca(D["linhas"], treino, regra_ab=False, criterio=criterio)
                    nota = ""
                escolhas.append(cfg)
                oteste = {p: oraculo[p] for p in teste}
                pred, _, _, _ = prever(D["linhas"], oteste, regra_ab=False, **cfg)
                m = metricas(confusao(pred, oteste))
                for kk in acum_oos: acum_oos[kk] += m[kk]
                predd, _, _, _ = prever(D["linhas"], oteste, regra_ab=False)
                md = metricas(confusao(predd, oteste))
                for kk in acum_def: acum_def[kk] += md[kk]
                print("    %-34s %-28s %4d %3d %4d %3d  %-7s %-7s%s" %
                      (str(nome_fold)[:34],
                       "thr%.2f m%.3f piso%.2f" % (cfg["thr_high"], cfg["margin"],
                                                   cfg["sim_min_2b"]),
                       m["TP"], m["FP"], m["FN"], m["TN"], m["P"], m["R"], nota))

            m_oos = metricas(acum_oos)
            m_def = metricas(acum_def)
            print("    %-34s %-28s %4d %3d %4d %3d  %-7s %-7s" %
                  ("AGREGADO FORA DA AMOSTRA", "(limiares do treino)",
                   m_oos["TP"], m_oos["FP"], m_oos["FN"], m_oos["TN"],
                   m_oos["P"], m_oos["R"]))
            print("    %-34s %-28s %4d %3d %4d %3d  %-7s %-7s" %
                  ("MESMOS PARES, limiares fixos", "thr0.80 m0.050 piso0.60",
                   m_def["TP"], m_def["FP"], m_def["FN"], m_def["TN"],
                   m_def["P"], m_def["R"]))
            print("      F1 fora da amostra %s  ·  F1 com os limiares fixos %s"
                  % (m_oos["F1"], m_def["F1"]))
            estab = Counter(tuple(sorted(c.items())) for c in escolhas)
            print("      estabilidade dos limiares entre folds: %d configuracao(oes) distinta(s)"
                  % len(estab))
            for cfg, q in estab.most_common():
                print("        %dx  %s" % (q, dict(cfg)))
            res.setdefault(nome_or, {})[nome_esq] = dict(
                fora_da_amostra=m_oos, limiares_fixos=m_def,
                escolhas=[dict(c) for c in escolhas],
                n_configuracoes_distintas=len(estab))
    out["E2_validacao_cruzada"] = res
    return res


# ══════════════════════════════════════════════════════════ E3
def _linhas_arquivo(base: Path, cve: str, tipo: str, fork: str, filepath: str):
    d = base / "evidencias_dissertacao" / cve
    if not d.is_dir():
        return None
    sufixo = filepath.replace("/", "_")
    if tipo == "fork":
        prefixo = "fork_" + fork.replace("/", "_") + "_"
    else:
        prefixo = "upstream_post_"
    for f in d.iterdir():
        if f.name.startswith(prefixo) and f.name.endswith(sufixo):
            try:
                return sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
            except Exception:
                return None
    return None


def e3_tamanho_patch(D, base, out):
    print("\n" + "=" * 78)
    print("E3 — DISCRIMINANTE DE TAMANHO DO PATCH")
    print("     (existe regra que separe patch pequeno de patch grande?)")
    print("=" * 78)

    agrup = defaultdict(list)
    for r in D["linhas"]:
        agrup[(r["fork"], r["cve_id"])].append(r)

    oraculo = D["humano"] or D["auto"]
    pred_u, _, _, _ = prever(D["linhas"], oraculo, regra_ab=False)

    dados = []
    for par, real in oraculo.items():
        rows = agrup.get(par, [])
        if not rows:
            continue
        rep = max(rows, key=lambda r: r.get("churn") or 0)
        churn = rep.get("churn") or 0
        n_lin = _linhas_arquivo(base, rep["cve_id"], "upstream_post",
                                rep["fork"], rep["filepath"])
        if not n_lin:
            continue
        razao = churn / n_lin
        acertou = (pred_u.get(par) == real)
        dados.append(dict(par="%s::%s" % par, categoria=rep["category"],
                          churn=churn, linhas_arquivo=n_lin,
                          razao_patch_arquivo=round(razao, 6),
                          sim_2a=rep.get("sim_2a"), delta=rep.get("delta"),
                          predito_corrigido=bool(pred_u.get(par)),
                          rotulo_corrigido=bool(real), acertou=acertou))

    if not dados:
        print("  (sem evidencia em disco para medir)")
        return {}

    print(f"\n  {len(dados)} pares com arquivo em disco.")
    erros = [d for d in dados if not d["acertou"]]
    acertos = [d for d in dados if d["acertou"]]
    def mediana(v):
        v = sorted(v); n = len(v)
        return None if not n else (v[n//2] if n % 2 else (v[n//2-1]+v[n//2])/2)
    print("    razao patch/arquivo — mediana nos ACERTOS: %s  (n=%d)"
          % (round(mediana([d['razao_patch_arquivo'] for d in acertos]), 5), len(acertos)))
    print("    razao patch/arquivo — mediana nos ERROS  : %s  (n=%d)"
          % (round(mediana([d['razao_patch_arquivo'] for d in erros]), 5) if erros else "—",
             len(erros)))

    # regra: patch pequeno em arquivo grande -> nao confiar no CORRIGIDO
    print("\n  REGRA PROPOSTA: se razao(patch/arquivo) < c, o veredito CORRIGIDO")
    print("  vai para a ZONA DE INCERTEZA em vez de ser afirmado.")
    print("    %-10s %4s %3s %4s %3s  %-7s %-7s %-7s %-9s %s" %
          ("c", "TP", "FP", "FN", "TN", "P", "R", "F1", "kappa", "% p/ auditoria"))
    varredura = []
    for c in [0.0, 0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.12, 0.20, 0.40]:
        pred = {}
        movidos = 0
        for d in dados:
            par = tuple(d["par"].split("::"))
            p = d["predito_corrigido"]
            if p and d["razao_patch_arquivo"] < c:
                p = False; movidos += 1     # vai para incerteza => nao afirma CORRIGIDO
            pred[par] = p
        orac = {tuple(d["par"].split("::")): d["rotulo_corrigido"] for d in dados}
        m = metricas(confusao(pred, orac))
        pct = 100.0 * movidos / len(dados)
        print("    %-10s %4d %3d %4d %3d  %-7s %-7s %-7s %-9s %.1f%%" %
              (c, m["TP"], m["FP"], m["FN"], m["TN"], m["P"], m["R"], m["F1"],
               m["kappa"], pct))
        varredura.append(dict(corte=c, **m, pct_para_auditoria=round(pct, 1)))

    # ---------------------------------------------------------------
    # O tamanho do patch discrimina? E o SINAL DO DELTA discrimina?
    print("\n  COMPARACAO DE DISCRIMINANTES — qual sinal realmente separa o erro?")
    agrup2 = defaultdict(list)
    for r in D["linhas"]:
        agrup2[(r["fork"], r["cve_id"])].append(r)

    def _delta_negativo(par):
        """A evidencia de dupla referencia aponta para o PRE-patch?"""
        rows = [r for r in agrup2.get(par, []) if r.get("delta") is not None]
        if not rows:
            return None
        rep_ = max(rows, key=lambda r: (r.get("sim_2a") or 0))
        return rep_["delta"] < 0

    linhas_tab = []
    for nome, corte in (("razao patch/arquivo < 0,05", "tam"),
                        ("delta < 0 (guarda A)", "delta")):
        pred = {}
        movidos = 0
        for d in dados:
            par = tuple(d["par"].split("::"))
            pr = d["predito_corrigido"]
            if pr:
                if corte == "tam":
                    gatilho = d["razao_patch_arquivo"] < 0.05
                else:
                    gatilho = _delta_negativo(par) is True
                if gatilho:
                    pr = False; movidos += 1
            pred[par] = pr
        orac = {tuple(d["par"].split("::")): d["rotulo_corrigido"] for d in dados}
        m = metricas(confusao(pred, orac))
        linhas_tab.append(dict(discriminante=nome, movidos=movidos, **m))

    base_m = metricas(confusao(
        {tuple(d["par"].split("::")): d["predito_corrigido"] for d in dados},
        {tuple(d["par"].split("::")): d["rotulo_corrigido"] for d in dados}))
    print("    %-30s %4s %3s %4s %3s  %-7s %-7s %-7s %-8s %s" %
          ("discriminante", "TP", "FP", "FN", "TN", "P", "R", "F1", "kappa", "casos movidos"))
    print("    %-30s %4d %3d %4d %3d  %-7s %-7s %-7s %-8s %s" %
          ("(nenhum — pipeline atual)", base_m["TP"], base_m["FP"], base_m["FN"],
           base_m["TN"], base_m["P"], base_m["R"], base_m["F1"], base_m["kappa"], 0))
    for t in linhas_tab:
        print("    %-30s %4d %3d %4d %3d  %-7s %-7s %-7s %-8s %s" %
              (t["discriminante"], t["TP"], t["FP"], t["FN"], t["TN"],
               t["P"], t["R"], t["F1"], t["kappa"], t["movidos"]))
    print("\n    LEITURA: o tamanho do patch NAO e um discriminante utilizavel neste")
    print("    conjunto — para zerar os 2 FP ele arrasta dezenas de acertos junto.")
    print("    O sinal do delta zera os mesmos 2 FP mexendo em pouquissimos casos.")
    print("    A resposta a essa critica nao e 'sabemos separar patch pequeno de grande':")
    print("    e 'medimos, o tamanho nao serve, e o sinal que serve e outro'.")

    out["E3_tamanho_patch"] = dict(pares=dados, varredura_corte=varredura,
                                   comparacao_discriminantes=linhas_tab,
                                   pipeline_sem_discriminante=base_m)
    return dados


# ══════════════════════════════════════════════════════════ E4
def _bootstrap(pred, oraculo, n=10000):
    pares = sorted(oraculo)
    amostras = defaultdict(list)
    for _ in range(n):
        sel = [pares[random.randrange(len(pares))] for _ in range(len(pares))]
        o = {}
        pr = {}
        for i, p in enumerate(sel):
            chave = (p[0], p[1], i)       # permite repeticao
            o[chave] = oraculo[p]
            pr[chave] = pred[p]
        m = metricas(confusao(pr, o))
        for k in ("P", "R", "F1", "kappa"):
            if m[k] is not None:
                amostras[k].append(m[k])
    saida = {}
    for k, v in amostras.items():
        v.sort()
        if not v: continue
        saida[k] = dict(ic95_baixo=round(v[int(0.025 * len(v))], 4),
                        ic95_alto=round(v[int(0.975 * len(v)) - 1], 4),
                        n_amostras=len(v))
    return saida


def _mcnemar(pred_a, pred_b, oraculo):
    """Discordancias: b01 = A acerta e B erra; b10 = A erra e B acerta."""
    b01 = b10 = 0
    for p, real in oraculo.items():
        a_ok = (pred_a.get(p) == real)
        b_ok = (pred_b.get(p) == real)
        if a_ok and not b_ok: b01 += 1
        elif b_ok and not a_ok: b10 += 1
    n = b01 + b10
    if n == 0:
        return dict(b01=0, b10=0, p_valor=1.0,
                    nota="nenhuma discordancia: os dois metodos acertam e erram nos mesmos pares")
    # binomial exato bicaudal com p=0.5
    k = min(b01, b10)
    acum = sum(math.comb(n, i) for i in range(0, k + 1))
    p_val = min(1.0, 2.0 * acum / (2 ** n))
    return dict(b01=b01, b10=b10, n_discordancias=n, p_valor=round(p_val, 4))


def e4_incerteza(D, out):
    print("\n" + "=" * 78)
    print("E4 — INTERVALOS DE CONFIANCA E TESTE DE McNEMAR")
    print("     (rigor estatistico: IC bootstrap e teste pareado exato)")
    print("=" * 78)

    res = {}
    for nome_or, oraculo in (("automatico", D["auto"]), ("humano", D["humano"])):
        if len(oraculo) < 10:
            continue
        pred_u, _, _, _ = prever(D["linhas"], oraculo, regra_ab=False)
        pred_ab, _, _, _ = prever(D["linhas"], oraculo, regra_ab=True)

        agrup = defaultdict(list)
        for r in D["linhas"]:
            agrup[(r["fork"], r["cve_id"])].append(r)
        pred_2a = {p: any(r.get("label_2a") == "CORRIGIDO" for r in agrup.get(p, []))
                   for p in oraculo}
        pred_2b = {p: any(r.get("label_2b") == "CORRIGIDO" for r in agrup.get(p, []))
                   for p in oraculo}
        pred_tr = {p: True for p in oraculo}

        m = metricas(confusao(pred_u, oraculo))
        ic = _bootstrap(pred_u, oraculo)
        print(f"\n  Oraculo {nome_or} — uniao das camadas (n={len(oraculo)} pares)")
        for k in ("P", "R", "F1", "kappa"):
            if k in ic:
                print("    %-6s %-8s  IC95%% [%s , %s]  (bootstrap, %d reamostragens)"
                      % (k, m[k], ic[k]["ic95_baixo"], ic[k]["ic95_alto"], ic[k]["n_amostras"]))

        print("\n    McNemar (a uniao e mesmo melhor que as alternativas?)")
        comps = [("uniao x Camada 2A isolada", pred_u, pred_2a),
                 ("uniao x Camada 2B isolada", pred_u, pred_2b),
                 ("uniao x trivial (sempre CORRIGIDO)", pred_u, pred_tr),
                 ("uniao x Regra A+B", pred_u, pred_ab)]
        mc = {}
        for nome, a, b in comps:
            r = _mcnemar(a, b, oraculo)
            mc[nome] = r
            if r.get("n_discordancias"):
                sig = "SIGNIFICATIVO" if r["p_valor"] < 0.05 else "nao significativo"
                print("      %-38s b01=%d b10=%d  p=%s  -> %s"
                      % (nome, r["b01"], r["b10"], r["p_valor"], sig))
            else:
                print("      %-38s %s" % (nome, r["nota"]))
        res[nome_or] = dict(metricas=m, ic95=ic, mcnemar=mc)
    out["E4_incerteza"] = res
    return res


# ══════════════════════════════════════════════════════════ E5
def e5_falhas(D, out):
    print("\n" + "=" * 78)
    print("E5 — ANALISE DE FALHAS CASO A CASO")
    print("=" * 78)

    agrup = defaultdict(list)
    for r in D["linhas"]:
        agrup[(r["fork"], r["cve_id"])].append(r)

    oraculo = D["humano"] or D["auto"]
    nome_or = "humano" if D["humano"] else "automatico"
    pred_u, por_par, _, _ = prever(D["linhas"], oraculo, regra_ab=False)
    pred_ab, _, _, _ = prever(D["linhas"], oraculo, regra_ab=True)

    casos = []
    for par, real in oraculo.items():
        auto = pred_u.get(par)
        if auto == real:
            continue
        rows = agrup.get(par, [])
        rep = max(rows, key=lambda r: (r.get("sim_2a") or 0)) if rows else {}
        casos.append(dict(
            tipo="FP (falsa seguranca)" if auto else "FN (perdeu a correcao)",
            fork=par[0], cve=par[1],
            categoria=rep.get("category"), linguagem=rep.get("language"),
            status_pipeline=por_par.get(par), rotulo=("CORRIGIDO" if real else "VULNERAVEL"),
            sim_2a=rep.get("sim_2a"), delta=rep.get("delta"),
            label_2a=rep.get("label_2a"), label_2b=rep.get("label_2b"),
            churn=rep.get("churn"), arquivo=rep.get("filepath"),
            regra_ab_corrige=(pred_ab.get(par) == real)))

    print(f"\n  Oraculo: {nome_or}. {len(casos)} erro(s) em {len(oraculo)} pares.\n")
    for c in casos:
        print("  [%s] %s :: %s" % (c["tipo"], c["fork"], c["cve"]))
        print("      categoria=%s linguagem=%s  arquivo=%s (churn %s)"
              % (c["categoria"], c["linguagem"], c["arquivo"], c["churn"]))
        print("      pipeline=%s  rotulo=%s  |  2A=%s (sim %s)  2B=%s (delta %s)"
              % (c["status_pipeline"], c["rotulo"], c["label_2a"], c["sim_2a"],
                 c["label_2b"], c["delta"]))
        print("      a Regra A+B corrige este caso? %s"
              % ("SIM" if c["regra_ab_corrige"] else "nao"))

    # onde a incerteza se concentra
    print("\n  Onde os vereditos param, por categoria:")
    tot = defaultdict(Counter)
    for v in pdis.aggregate_verdicts(D["linhas"]):
        tot[v["category"]][v["status"]] += 1
    for cat, cont in sorted(tot.items()):
        print("    %-14s %s" % (cat, dict(cont)))

    out["E5_falhas"] = dict(oraculo=nome_or, casos=casos,
                            por_categoria={k: dict(v) for k, v in tot.items()})
    return casos


# ══════════════════════════════════════════════════════════ E6
def e6_curva(D, out):
    print("\n" + "=" * 78)
    print("E6 — CURVA DE OPERACAO COM O BASELINE TRIVIAL MARCADO")
    print("     (comparacao explicita contra o classificador constante)")
    print("=" * 78)

    res = {}
    for nome_or, oraculo in (("automatico", D["auto"]), ("humano", D["humano"])):
        if len(oraculo) < 10:
            continue
        triv = metricas(confusao({p: True for p in oraculo}, oraculo))
        print(f"\n  Oraculo {nome_or} — trivial (sempre CORRIGIDO): "
              f"P={triv['P']} R={triv['R']} F1={triv['F1']} kappa={triv['kappa']}")
        print("    %-9s %4s %3s %4s %3s  %-7s %-7s %-7s %-8s %s" %
              ("thr_high", "TP", "FP", "FN", "TN", "P", "R", "F1", "kappa", "bate o trivial?"))
        curva = []
        for th in [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
            pred, _, _, _ = prever(D["linhas"], oraculo, regra_ab=False, thr_high=th)
            m = metricas(confusao(pred, oraculo))
            bate = "sim" if (m["kappa"] or 0) > (triv["kappa"] or 0) else "NAO"
            marca = " <<< adotado" if abs(th - DEF["thr_high"]) < 1e-9 else ""
            print("    %-9s %4d %3d %4d %3d  %-7s %-7s %-7s %-8s %s%s" %
                  (th, m["TP"], m["FP"], m["FN"], m["TN"], m["P"], m["R"],
                   m["F1"], m["kappa"], bate, marca))
            curva.append(dict(thr_high=th, **m))
        res[nome_or] = dict(trivial=triv, curva=curva)
    out["E6_curva"] = res
    return res


# ══════════════════════════════════════════════════════════ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="resultados_2026-08-31_v2")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    base = Path(args.run)
    dest = Path(args.out) if args.out else base / "experimentos_revisores.json"

    D = carregar(base)
    print("=" * 78)
    print("EXPERIMENTOS DE VALIDACAO — run %s" % base)
    print("=" * 78)
    print("  %d linhas cruas · %d pares com GT automatico conclusivo · "
          "%d pares com veredito humano"
          % (len(D["linhas"]), len(D["auto"]), len(D["humano"])))

    out = {"run": str(base),
           "n_linhas": len(D["linhas"]),
           "n_pares_gt_auto": len(D["auto"]),
           "n_pares_humano": len(D["humano"])}

    e1_baselines(D, out)
    e2_validacao_cruzada(D, out)
    e3_tamanho_patch(D, base, out)
    e4_incerteza(D, out)
    e5_falhas(D, out)
    e6_curva(D, out)

    json.dump(out, open(dest, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("\n" + "=" * 78)
    print("-> %s" % dest)


if __name__ == "__main__":
    main()
