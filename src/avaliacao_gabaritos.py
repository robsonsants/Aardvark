#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Avaliação do método contra os gabaritos, a partir das linhas cruas de uma execução.

  E1  Classificador trivial, camadas isoladas e as duas configurações do método
  E2  Intervalos de confiança (bootstrap) e teste de McNemar
  E3  Erros caso a caso
  E4  Análise de sensibilidade do limiar superior da Camada 2A

Tudo offline. Nenhum limiar muda uma medida: sim_2a, sim_patch, sim_vuln e delta já
estão gravados nas linhas cruas, e os limiares só mudam como esses números viram
rótulo. Não há rede, token nem reprocessamento da árvore sintática.

Uso:
    python src/avaliacao_gabaritos.py --run resultados/matrix/top10
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

random.seed(20260908)   # reprodutibilidade do bootstrap


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
def e1_classificadores(D, out):
    print("\n" + "=" * 78)
    print("E1 — CLASSIFICADOR TRIVIAL, CAMADAS ISOLADAS E CONFIGURACOES")
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
        # constante: sempre CORRIGIDO
        linha["trivial: sempre CORRIGIDO"] = metricas(
            confusao({p: True for p in oraculo}, oraculo))
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

    # leitura
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
    out["E1_classificadores"] = res
    return res


# ══════════════════════════════════════════════════════════ E2
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


def e2_incerteza(D, out):
    print("\n" + "=" * 78)
    print("E2 — INTERVALOS DE CONFIANCA E TESTE DE McNEMAR")
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

        m = metricas(confusao(pred_u, oraculo))
        ic = _bootstrap(pred_u, oraculo)
        print(f"\n  Oraculo {nome_or} — uniao das camadas (n={len(oraculo)} pares)")
        for k in ("P", "R", "F1", "kappa"):
            if k in ic:
                print("    %-6s %-8s  IC95%% [%s , %s]  (bootstrap, %d reamostragens)"
                      % (k, m[k], ic[k]["ic95_baixo"], ic[k]["ic95_alto"], ic[k]["n_amostras"]))

        print("\n    McNemar")
        comps = [("uniao x Camada 2A isolada", pred_u, pred_2a),
                 ("uniao x Camada 2B isolada", pred_u, pred_2b),
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

    # configuração A+B, depois da União, com o mesmo procedimento
    for nome_or, oraculo in (("automatico", D["auto"]), ("humano", D["humano"])):
        if len(oraculo) < 10:
            continue
        pred_ab, _, _, _ = prever(D["linhas"], oraculo, regra_ab=True)
        m = metricas(confusao(pred_ab, oraculo))
        ic = _bootstrap(pred_ab, oraculo)
        print(f"\n  Oraculo {nome_or} — configuracao A+B (n={len(oraculo)} pares)")
        for k in ("P", "R", "F1", "kappa"):
            if k in ic:
                print("    %-6s %-8s  IC95%% [%s , %s]  (bootstrap, %d reamostragens)"
                      % (k, m[k], ic[k]["ic95_baixo"], ic[k]["ic95_alto"], ic[k]["n_amostras"]))
        res[nome_or]["regra_ab"] = dict(metricas=m, ic95=ic)
    out["E2_incerteza"] = res
    return res


# ══════════════════════════════════════════════════════════ E3
def e3_falhas(D, out):
    print("\n" + "=" * 78)
    print("E3 — ERROS CASO A CASO")
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

    out["E3_falhas"] = dict(oraculo=nome_or, casos=casos,
                            por_categoria={k: dict(v) for k, v in tot.items()})
    return casos


# ══════════════════════════════════════════════════════════ E4
def e4_sensibilidade(D, out):
    print("\n" + "=" * 78)
    print("E4 — ANALISE DE SENSIBILIDADE DO LIMIAR SUPERIOR DA CAMADA 2A")
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
    out["E4_sensibilidade"] = res
    return res


# ══════════════════════════════════════════════════════════ main
def _posicionar_gerador(D):
    """Leva o gerador aleatório ao estado em que o bootstrap do E2 começa, para que os
    intervalos de confiança saiam iguais aos publicados."""
    for oraculo in (D["auto"], D["humano"]):
        if len(oraculo) < 10:
            continue
        pares = sorted(oraculo)
        pos = [p for p in pares if oraculo[p]]
        neg = [p for p in pares if not oraculo[p]]
        random.shuffle(pos); random.shuffle(neg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="resultados/matrix/top10")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    base = Path(args.run)
    dest = Path(args.out) if args.out else base / "avaliacao_gabaritos.json"

    D = carregar(base)
    print("=" * 78)
    print("AVALIACAO CONTRA OS GABARITOS — run %s" % base)
    print("=" * 78)
    print("  %d linhas cruas · %d pares com GT automatico conclusivo · "
          "%d pares com veredito humano"
          % (len(D["linhas"]), len(D["auto"]), len(D["humano"])))

    out = {"run": str(base),
           "n_linhas": len(D["linhas"]),
           "n_pares_gt_auto": len(D["auto"]),
           "n_pares_humano": len(D["humano"])}

    e1_classificadores(D, out)
    _posicionar_gerador(D)
    e2_incerteza(D, out)
    e3_falhas(D, out)
    e4_sensibilidade(D, out)

    json.dump(out, open(dest, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("\n" + "=" * 78)
    print("-> %s" % dest)


if __name__ == "__main__":
    main()
