# -*- coding: utf-8 -*-
"""
Shared core for reproducing the related-work methodologies ON the same Matrix
ecosystem fork data, so each one becomes a measurable baseline rather than a citation.

Idea: the main pipeline already records, per (upstream, fork, CVE, file), the signal
each state-of-the-art technique relies on. Here we ISOLATE each technique and evaluate
it as an independent baseline, producing the empirical comparison (false-negative
reduction, macro coverage, time lag).

Signal source: resultados_2026-07-04/dissertation_resultados.json
  sha_match            -> Wyss et al. 2022  (whole-file hash)
  sim_2a / label_2a    -> VERCATION, Cheng et al. 2025 (AST + edit distance)
  sim_patch/sim_vuln/delta/label_2b -> PPTFI/PatchDiscovery (dual-reference PPT)
  status (final union) -> coverage matrix -> See et al. 2025 (greedy set cover/Pareto)
"""
import json, os, sys, datetime

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(PROJ, "resultados_2026-07-04")
DEFAULT_RESULTS = os.path.join(RESULTS_DIR, "dissertation_resultados.json")
DEFAULT_GT_METRICS = os.path.join(RESULTS_DIR, "gt_dissertation_metricas.json")

# Diretório de saída datado (não misturar com execuções anteriores).
# Sobrescreva com a env var RW_DATE=AAAA-MM-DD se precisar fixar a data.
TODAY = os.getenv("RW_DATE", datetime.date.today().isoformat())
OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"resultados_{TODAY}")
os.makedirs(OUTDIR, exist_ok=True)

# Prioridade para unir múltiplos arquivos/commits do mesmo par (regra da união).
STATUS_PRIORITY = {
    "CORRIGIDO": 4, "ZONA_INCERTEZA": 3, "VULNERAVEL": 2,
    "NAO_CORRIGIDO": 2, "FILE_NOT_FOUND": 1, "": 0, None: 0,
}


def load_rows(path=DEFAULT_RESULTS):
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("resultados") or next(
            (v for v in data.values() if isinstance(v, list)), [])
    return data


def key(r):
    return f"{r['upstream']}::{r['fork']}::{r['cve_id']}"


def _best(cur, new):
    return new if STATUS_PRIORITY.get(new, 0) >= STATUS_PRIORITY.get(cur, 0) else cur


def agg_by_key(rows):
    """Agrega por (upstream, fork, CVE) unindo os vereditos de cada técnica."""
    agg = {}
    for r in rows:
        k = key(r)
        a = agg.setdefault(k, {
            "upstream": r["upstream"], "fork": r["fork"], "cve_id": r["cve_id"],
            "category": r.get("category"), "language": r.get("language"),
            "hash_patched": False, "ast_label": "", "dualref_label": "",
            "status": "", "sim_2a_max": None,
        })
        if r.get("sha_match"):
            a["hash_patched"] = True
        a["ast_label"] = _best(a["ast_label"], r.get("label_2a") or "")
        a["dualref_label"] = _best(a["dualref_label"], r.get("label_2b") or "")
        a["status"] = _best(a["status"], r.get("status") or "")
        s = r.get("sim_2a")
        if s is not None:
            a["sim_2a_max"] = s if a["sim_2a_max"] is None else max(a["sim_2a_max"], s)
    return agg


def load_gt_pairs(path=DEFAULT_GT_METRICS):
    """Pares fork×CVE com ground truth conclusivo (todos CONFIRMED_PATCHED aqui)."""
    m = json.load(open(path, encoding="utf-8"))
    return {p["chave"]: p for p in m.get("pares", [])}, m


def out_path(script_file, name="resultado.json"):
    return os.path.join(os.path.dirname(os.path.abspath(script_file)), name)


def dump(script_file, obj, name="resultado.json"):
    p = out_path(script_file, name)
    json.dump(obj, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return p


def dump_dated(fname, obj):
    """Grava no diretório datado compartilhado (resultados_AAAA-MM-DD/)."""
    p = os.path.join(OUTDIR, fname)
    json.dump(obj, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return p
