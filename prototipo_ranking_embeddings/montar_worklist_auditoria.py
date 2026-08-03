# -*- coding: utf-8 -*-
"""
Prepares the NEGATIVE SET for MANUAL AUDIT.

It does not make the judgement -- that is the human reviewer's job. It produces a
worklist spreadsheet in which every negative instance (supposedly vulnerable code)
already carries:
  - CVE, upstream, fork, target function, language;
  - the automatic verdict of each method (embeddings and AST-2A);
  - whether the case is DISPUTED (some method called a negative patched -> a candidate
    false positive worth checking), sorted to the top;
  - links to the REFERENCE (the fix commit) and to the FILE in the fork;
  - empty `veredito_humano` (human verdict) and `observacao` (notes) columns to fill in.

Depois de preenchida, `calcular_auditoria.py` recomputa precision/recall/F1 sobre
os rótulos humanos.
"""
import os, sys, json, csv
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

RESULTS = os.path.join(PROJ, "resultados_2026-07-04", "dissertation_resultados.json")
EVAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "resultados_2026-07-09", "precision_eval.json")

rows = json.load(open(RESULTS, encoding="utf-8"))
ev = json.load(open(EVAL, encoding="utf-8"))["instancias"]

# (upstream, cve) -> shas e arquivos do fix
fix = defaultdict(lambda: {"shas": set(), "files": set()})
for r in rows:
    if r.get("fix_sha") and r.get("filepath"):
        fix[(r["upstream"], r["cve_id"])]["shas"].add(r["fix_sha"])
        fix[(r["upstream"], r["cve_id"])]["files"].add(r["filepath"])


def emb_verdict(x):
    if x["emb_sp"] is None:
        return "?"
    return "CORRIGIDO" if (x["emb_sp"] - x["emb_sv"]) > 0 else "VULNERAVEL"


def ast_verdict(x):
    if x["ast_sim_patch"] is None:
        return "?"
    return "CORRIGIDO" if x["ast_sim_patch"] >= 0.80 else "VULNERAVEL"


out = []
for x in ev:
    if x["label"] != "VULNERABLE":            # só o conjunto NEGATIVO
        continue
    up, cve = x["upstream"], x["cve"]
    shas = sorted(fix[(up, cve)]["shas"])
    files = sorted(fix[(up, cve)]["files"])
    gabarito = " | ".join(f"https://github.com/{up}/commit/{s}" for s in shas)
    if x["source"] == "upstream_pre":
        alvo = up + " @pre-fix"
        url_fork = " | ".join(f"https://github.com/{up}/blob/{shas[0]}~1/{f}" for f in files) if shas else ""
    else:                                      # fork_pre
        alvo = x["fork"]
        url_fork = " | ".join(f"https://github.com/{x['fork']}/commits/HEAD/{f}" for f in files)
    ve, va = emb_verdict(x), ast_verdict(x)
    disputado = (ve == "CORRIGIDO") or (va == "CORRIGIDO")   # negativo dito CORRIGIDO = possível FP
    out.append({
        "prioridade": "DISPUTADO" if disputado else "ok",
        "cve": cve, "upstream": up, "instancia": alvo, "origem": x["source"],
        "lang": x["lang"], "funcao_alvo": x["target"],
        "verdito_embeddings": ve, "verdito_ast2a": va,
        "url_gabarito_fix": gabarito, "url_arquivo_fork": url_fork,
        "veredito_humano": "", "observacao": "",
    })

# disputados primeiro
out.sort(key=lambda r: (r["prioridade"] != "DISPUTADO", r["cve"], r["instancia"]))

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auditoria_negativos_worklist.csv")
with open(path, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader(); w.writerows(out)

nd = sum(1 for r in out if r["prioridade"] == "DISPUTADO")
print(f"Negativos no worklist : {len(out)}")
print(f"  DISPUTADOS (checar)  : {nd}  (algum método disse CORRIGIDO sobre código vulnerável)")
print(f"  origem upstream_pre  : {sum(1 for r in out if r['origem']=='upstream_pre')}")
print(f"  origem fork_pre      : {sum(1 for r in out if r['origem']=='fork_pre')}")
print(f"-> {path}")
print("\nPreencha a coluna 'veredito_humano' com VULNERAVEL ou CORRIGIDO e rode calcular_auditoria.py")
