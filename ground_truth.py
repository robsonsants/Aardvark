"""
ground_truth.py  -  Automated ground-truth construction and validation
==========================================================================
Validates Layer 2 (AST) by measuring Precision/Recall/F1/Kappa against an
INDEPENDENT ground truth, built by searching the patch KEY LINES in the fork's code.
Being independent of the method under test is what makes it a valid reference.

This is the AUTOMATED oracle. It is not the only one: auditoria_manual.py builds the
HUMAN oracle over the same pairs, and every reported figure names which oracle it came
from. Agreement between the two on the published run is 36/41 = 87.8%.

How the pairs are chosen:
  - The forks to validate are NOT a fixed list. They are read dynamically from
    dissertation_resultados.json (the raw records produced by
    pipeline_dissertation.py): every (upstream, CVE, fork, fix_sha) becomes a
    ground-truth task.
  - Metrics cross the ground truth against the AUTOMATED verdict, aggregated by
    union across the fix commits of the same CVE.

Ground-truth strategy (independent of the AST method):
  - Extract the lines added/removed by the fix commit (real upstream diff)
  - Normalise whitespace, tabs and comments
  - Search each key line in the fork's file (normalised exact match + fuzzy, 0.85)
  - Label per (fork, CVE): CONFIRMED_PATCHED / CONFIRMED_VULNERABLE / AMBIGUOUS

Ground truth x automatic classifier (for each fork x CVE with a conclusive label):
  GT=PATCHED    & auto=CORRIGIDO  -> TP
  GT=VULNERABLE & auto=CORRIGIDO  -> FP  (false sense of security -- the severe error)
  GT=PATCHED    & auto!=CORRIGIDO -> FN
  GT=VULNERABLE & auto!=CORRIGIDO -> TN

Known limitation: the first lines of a diff are often imports/docstrings/context, so
confidence can be contaminated by noise. This motivated ground truth v2, which anchors
on the corrective line; see resultados_2026-07-04/VALIDACAO_GROUND_TRUTH.md.

Usage:
    python ground_truth.py --token YOUR_TOKEN
    python ground_truth.py --token YOUR_TOKEN --upstream element-hq/synapse
    python ground_truth.py --token YOUR_TOKEN \
        --results resultados_YYYY-MM-DD/dissertation_resultados.json \
        --outdir  resultados_YYYY-MM-DD

Outputs:
    gt_dissertation_resultados.json   -- ground truth per (fork, CVE, fix_sha) + evidence
    gt_dissertation_resultados.csv    -- flat table
    gt_dissertation_metricas.json     -- Precision, Recall, F1, Accuracy, Kappa
    evidencias_gt_dissertacao/        -- fork files downloaded for auditing
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from collections import defaultdict
from difflib import SequenceMatcher

# Windows: forçar UTF-8 no console (evita UnicodeEncodeError com '→', '✓', '⚠').
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests
import pandas as pd

# Reusa a mesma regra de agregação por união entre fix commits usada na
# dissertação, para que o "veredito automático" comparado ao GT seja idêntico
# ao que o pipeline_dissertation.py reporta.
from pipeline_dissertation import aggregate_verdicts

RESULTS_JSON = "dissertation_resultados.json"
OUT_JSON     = "gt_dissertation_resultados.json"
OUT_CSV      = "gt_dissertation_resultados.csv"
MET_JSON     = "gt_dissertation_metricas.json"
EVIDENCE_DIR = "evidencias_gt_dissertacao"


# ─── GitHub API ───────────────────────────────────────────────────────────────
class GitHub:
    BASE = "https://api.github.com"

    def __init__(self, token: str):
        self.token = token
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        })

    def _get(self, url, params=None):
        for _ in range(3):
            try:
                r = self.s.get(url, params=params, timeout=30)
            except requests.RequestException as e:
                print(f"  [rede] {e}")
                return None
            if r.status_code == 404:
                return None
            if r.status_code == 403:
                wait = max(
                    int(r.headers.get("X-RateLimit-Reset", time.time() + 61))
                    - time.time(), 1)
                print(f"  [rate limit] aguardando {wait:.0f}s...")
                time.sleep(wait)
                continue
            if not r.ok:
                return None
            return r.json()
        return None

    def rate_limit(self):
        d = self._get(f"{self.BASE}/rate_limit")
        if d:
            c = d["resources"]["core"]
            print(f"  Rate limit: {c['remaining']}/{c['limit']}")

    def file_at(self, owner, repo, path, ref):
        d = self._get(
            f"{self.BASE}/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
        )
        if not d or "content" not in d:
            return None
        return base64.b64decode(d["content"]).decode("utf-8", errors="replace")

    def commit_diff_lines(self, owner, repo, sha, filepath):
        """
        Retorna (added, removed): linhas adicionadas e removidas pelo patch para
        o arquivo alvo. São as linhas-chave que definem a correção de segurança.
        """
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3.diff",
        }
        try:
            r = requests.get(
                f"{self.BASE}/repos/{owner}/{repo}/commits/{sha}",
                headers=headers, timeout=30,
            )
        except requests.RequestException as e:
            print(f"  [rede/diff] {e}")
            return [], []
        if not r.ok:
            return [], []

        added, removed = [], []
        in_file = False
        for line in r.text.split('\n'):
            if line.startswith('diff --git'):
                in_file = filepath in line
            if not in_file:
                continue
            if line.startswith('+') and not line.startswith('+++'):
                code = line[1:].strip()
                if code and not code.startswith('//') and not code.startswith('#') \
                   and len(code) > 3:
                    added.append(code)
            elif line.startswith('-') and not line.startswith('---'):
                code = line[1:].strip()
                if code and not code.startswith('//') and not code.startswith('#') \
                   and len(code) > 3:
                    removed.append(code)
        return added, removed


# ─── Normalização e busca de linhas ──────────────────────────────────────────
def normalize(text: str) -> str:
    text = re.sub(r'\s+', ' ', text).strip()
    text = text.replace('\t', ' ')
    return text


def line_present(line: str, content: str,
                 threshold: float = 0.85):
    """Retorna (presente, score, linha_mais_próxima)."""
    norm_line = normalize(line)
    norm_content_lines = [normalize(l) for l in content.split('\n')]

    if norm_line in norm_content_lines:
        return True, 1.0, norm_line

    best_score, best_match = 0.0, ""
    for cl in norm_content_lines:
        if len(cl) < 3:
            continue
        score = SequenceMatcher(None, norm_line, cl).ratio()
        if score > best_score:
            best_score, best_match = score, cl
    return best_score >= threshold, best_score, best_match


# ─── Verificação de ground truth por (fork, CVE, fix_sha) ─────────────────────
def verify_fork_gt(task: dict, gh: GitHub,
                   added_lines: list, removed_lines: list,
                   evidence_dir: str) -> dict:
    """
    Verifica se as linhas-chave do patch estão no fork.
      - patch de adição: presença das linhas adicionadas → corrigido
      - patch de remoção: presença das linhas removidas → ainda vulnerável
    """
    fork     = task["fork"]
    fo, fr   = fork.split("/", 1)
    filepath = task["filepath"]
    cve      = task["cve"]
    fix_sha  = task["fix_sha"]

    base = {
        "upstream":  task["upstream"],
        "category":  task["category"],
        "cve":       cve,
        "fork":      fork,
        "fix_sha":   fix_sha,
        "filepath":  filepath,
        "tipo":      task["tipo"],
        "auto_status": task["auto_status"],
        "sim_ast":   task["sim_ast"],
    }

    code_fork = gh.file_at(fo, fr, filepath, "HEAD")
    if not code_fork:
        base.update({"gt_label": "INACESSIVEL", "gt_confidence": 0.0,
                     "lines_checked": 0, "lines_present": 0, "lines_absent": 0,
                     "is_removal_patch": False, "line_details": [],
                     "evidence_file": None})
        return base

    os.makedirs(evidence_dir, exist_ok=True)
    fname = f"{fo}_{fr}_{fix_sha[:8]}_{filepath.replace('/', '_')}"
    with open(f"{evidence_dir}/{fname}", "w", encoding="utf-8") as f:
        f.write(code_fork)

    is_removal_patch = len(removed_lines) > len(added_lines) * 2
    probe = (removed_lines if is_removal_patch else added_lines)[:15]
    ptype = "removed" if is_removal_patch else "added"

    line_results = []
    for line in probe:
        present, score, match = line_present(line, code_fork)
        line_results.append({
            "line": line[:80], "type": ptype,
            "present_in_fork": present,
            "score": round(score, 3), "match": match[:80],
        })

    if not line_results:
        base.update({"gt_label": "AMBIGUOUS", "gt_confidence": 0.0,
                     "lines_checked": 0, "lines_present": 0, "lines_absent": 0,
                     "is_removal_patch": is_removal_patch, "line_details": [],
                     "evidence_file": f"{evidence_dir}/{fname}"})
        return base

    n_checked = len(line_results)
    n_present = sum(1 for r in line_results if r["present_in_fork"])
    n_absent  = n_checked - n_present
    # remoção: linha AUSENTE = corrigido; adição: linha PRESENTE = corrigido
    ratio_patched = (n_absent if is_removal_patch else n_present) / n_checked
    confidence = ratio_patched

    if confidence >= 0.70:
        gt_label = "CONFIRMED_PATCHED"
    elif confidence <= 0.30:
        gt_label = "CONFIRMED_VULNERABLE"
    else:
        gt_label = "AMBIGUOUS"

    print(f"    [{task['tipo']:<13}] {fork:<38} auto={task['auto_status']:<14} "
          f"conf={confidence:.0%} → {gt_label}")

    base.update({
        "gt_label": gt_label,
        "gt_confidence": round(confidence, 4),
        "is_removal_patch": is_removal_patch,
        "lines_checked": n_checked,
        "lines_present": n_present,
        "lines_absent": n_absent,
        "line_details": line_results,
        "evidence_file": f"{evidence_dir}/{fname}",
    })
    return base


# ─── Carregar tarefas de GT a partir dos resultados da dissertação ───────────
_TIPO_POR_STATUS = {
    "CORRIGIDO":      "L2_CORRIGIDO",
    "ZONA_INCERTEZA": "ZONA_INCERTEZA",
    "VULNERAVEL":     "VULNERAVEL",
    "NAO_CORRIGIDO":  "VULNERAVEL",
    "FILE_NOT_FOUND": "FILE_NOT_FOUND",
}


def load_gt_tasks(results_path: str, upstream_filter: str = None):
    """
    Lê dissertation_resultados.json (linhas cruas) e devolve:
      - raw:   as linhas cruas (para agregar o veredito automático)
      - tasks: uma tarefa de GT por linha crua elegível
    Uma linha é elegível se o arquivo existe no fork (status != FILE_NOT_FOUND).
    Linhas com SHA match viram GT automático (PATCHED) sem chamada extra.
    """
    with open(results_path, encoding="utf-8") as f:
        raw = json.load(f)

    tasks = []
    for r in raw:
        up = r["upstream"]
        if upstream_filter and up != upstream_filter:
            continue
        if r["status"] == "FILE_NOT_FOUND":
            continue  # sem arquivo no fork → sem GT possível
        owner, repo = up.split("/", 1)
        sha_match = bool(r.get("sha_match"))
        tasks.append({
            "upstream":       up,
            "upstream_owner": owner,
            "upstream_repo":  repo,
            "category":       r.get("category", ""),
            "cve":            r["cve_id"],
            "fix_sha":        r["fix_sha"],
            "filepath":       r["filepath"],
            "lang":           r.get("language", ""),
            "fork":           r["fork"],
            "sha_match":      sha_match,
            "auto_status":    r["status"],
            "tipo":           "L1_SHA" if sha_match else _TIPO_POR_STATUS.get(r["status"], r["status"]),
            "sim_ast":        r.get("sim_2a") if r.get("sim_2a") is not None else (r.get("sim_patch") or 0.0),
        })
    return raw, tasks


# ─── Agregação do GT por (upstream, fork, CVE) — regra da união ──────────────
_GT_PRIORITY = {"CONFIRMED_PATCHED": 4, "CONFIRMED_VULNERABLE": 3,
                "AMBIGUOUS": 2, "INACESSIVEL": 1}


def aggregate_gt(gt_rows: list) -> dict:
    """Colapsa múltiplos fix commits: PATCHED se algum commit confirma correção."""
    groups = defaultdict(list)
    for g in gt_rows:
        groups[(g["upstream"], g["fork"], g["cve"])].append(g)
    out = {}
    for key, rows in groups.items():
        best = max(rows, key=lambda g: _GT_PRIORITY.get(g["gt_label"], 0))
        out[key] = best["gt_label"]
    return out


# ─── Métricas Precisão/Recall/F1/Kappa contra o veredito automático ──────────
def calcular_metricas(gt_rows: list, raw_results: list) -> dict:
    # Veredito automático agregado por (upstream, fork, cve)
    auto = {(v["upstream"], v["fork"], v["cve_id"]): v["status"]
            for v in aggregate_verdicts(raw_results)}
    gt = aggregate_gt(gt_rows)

    tp = fp = fn = tn = 0
    pares = []
    for key, gt_label in gt.items():
        if gt_label not in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
            continue  # AMBIGUOUS / INACESSIVEL não entram nas métricas
        auto_status = auto.get(key, "FILE_NOT_FOUND")
        pred_corrigido = (auto_status == "CORRIGIDO")
        gt_patched = (gt_label == "CONFIRMED_PATCHED")
        if gt_patched and pred_corrigido:       tp += 1
        elif not gt_patched and pred_corrigido: fp += 1
        elif gt_patched and not pred_corrigido: fn += 1
        else:                                   tn += 1
        pares.append({"chave": "::".join(key), "gt": gt_label,
                      "auto": auto_status, "pred_corrigido": pred_corrigido})

    n    = tp + fp + fn + tn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec  = tp / (tp + fn) if tp + fn else 0.0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc  = (tp + tn) / n if n else 0.0

    p_obs = acc
    p_yes = ((tp + fp) / n) * ((tp + fn) / n) if n else 0
    p_no  = ((fn + tn) / n) * ((fp + tn) / n) if n else 0
    p_exp = p_yes + p_no
    kappa = (p_obs - p_exp) / (1 - p_exp) if (1 - p_exp) != 0 else 0.0

    n_amb = sum(1 for g in gt.values() if g == "AMBIGUOUS")
    n_inac = sum(1 for g in gt.values() if g == "INACESSIVEL")

    return {
        "n_pares_fork_cve":   len(gt),
        "n_com_gt_conclusivo": n,
        "n_ambiguous":        n_amb,
        "n_inacessivel":      n_inac,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision":   round(prec, 4),
        "recall":      round(rec, 4),
        "f1_score":    round(f1, 4),
        "accuracy":    round(acc, 4),
        "kappa_cohen": round(kappa, 4),
        "falsos_positivos_graves": fp,
        "nota_fp": ("ATENÇÃO: FP = classificador marcou CORRIGIDO um fork que o "
                    "GT confirma VULNERÁVEL — falsa sensação de segurança")
                   if fp > 0 else "OK (nenhum falso positivo grave)",
        "pares": pares,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Ground Truth da dissertação (dinâmico, por linhas-chave)")
    ap.add_argument("--token", required=True, help="GitHub Personal Access Token")
    ap.add_argument("--results", default=RESULTS_JSON,
                    help=f"Linhas cruas da dissertação (padrão: {RESULTS_JSON})")
    ap.add_argument("--upstream", default=None,
                    help="Filtrar por upstream (ex.: element-hq/synapse)")
    ap.add_argument("--outdir", default=None,
                    help="Diretório da execução: lê dissertation_resultados.json de "
                         "lá e grava os arquivos de GT lá (não mistura execuções).")
    args = ap.parse_args()

    # Se --outdir e o usuário não passou --results, ler os resultados de dentro dele.
    results_path = args.results
    if args.outdir and args.results == RESULTS_JSON:
        results_path = os.path.join(args.outdir, RESULTS_JSON)

    if not os.path.exists(results_path):
        print(f"ERRO: {results_path} não encontrado. Rode pipeline_dissertation.py antes.")
        return

    gh = GitHub(args.token)
    gh.rate_limit()

    raw, tasks = load_gt_tasks(results_path, args.upstream)

    # A partir daqui as saídas são relativas: mudar para o outdir isola o GT.
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        os.chdir(args.outdir)
    print(f"\nTarefas de GT (linhas cruas elegíveis): {len(tasks)}")

    patch_cache = {}   # (owner, repo, sha, filepath) → (added, removed)
    gt_rows = []

    for task in tasks:
        # SHA match → corrigido por definição (arquivo idêntico ao pós-patch)
        if task["sha_match"]:
            gt_rows.append({
                "upstream": task["upstream"], "category": task["category"],
                "cve": task["cve"], "fork": task["fork"], "fix_sha": task["fix_sha"],
                "filepath": task["filepath"], "tipo": "L1_SHA",
                "auto_status": task["auto_status"], "sim_ast": task["sim_ast"],
                "gt_label": "CONFIRMED_PATCHED", "gt_confidence": 1.0,
                "is_removal_patch": False, "lines_checked": 0,
                "lines_present": 0, "lines_absent": 0, "line_details": [],
                "evidence_file": None,
            })
            print(f"    [L1_SHA       ] {task['fork']:<38} auto={task['auto_status']:<14} → CONFIRMED_PATCHED (auto)")
            continue

        key = (task["upstream_owner"], task["upstream_repo"],
               task["fix_sha"], task["filepath"])
        if key not in patch_cache:
            added, removed = gh.commit_diff_lines(*key)
            patch_cache[key] = (added, removed)
        added, removed = patch_cache[key]

        gt_rows.append(verify_fork_gt(
            task, gh, added, removed,
            evidence_dir=f"{EVIDENCE_DIR}/{task['cve']}",
        ))
        time.sleep(0.2)

    metricas = calcular_metricas(gt_rows, raw)

    # ── Relatório ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("MÉTRICAS — Camada 2 (AST) vs Ground Truth")
    print(f"{'='*60}")
    print(f"  Pares fork×CVE:          {metricas['n_pares_fork_cve']}")
    print(f"  Com GT conclusivo:       {metricas['n_com_gt_conclusivo']}")
    print(f"  Ambíguos / inacessíveis: {metricas['n_ambiguous']} / {metricas['n_inacessivel']}")
    print(f"  TP={metricas['TP']}  FP={metricas['FP']}  FN={metricas['FN']}  TN={metricas['TN']}")
    print(f"  Precision : {metricas['precision']:.4f}")
    print(f"  Recall    : {metricas['recall']:.4f}")
    print(f"  F1-Score  : {metricas['f1_score']:.4f}")
    print(f"  Accuracy  : {metricas['accuracy']:.4f}")
    print(f"  Kappa     : {metricas['kappa_cohen']:.4f}")
    if metricas["falsos_positivos_graves"] > 0:
        print(f"\n  ⚠  {metricas['nota_fp']}")

    # ── Salvar ───────────────────────────────────────────────────────────────
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(gt_rows, f, indent=2, ensure_ascii=False)
    pd.DataFrame(gt_rows).drop(columns=["line_details"], errors="ignore") \
        .to_csv(OUT_CSV, index=False, sep=";")
    with open(MET_JSON, "w", encoding="utf-8") as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)

    print(f"\n  Arquivos gerados:")
    print(f"    {OUT_JSON}")
    print(f"    {OUT_CSV}")
    print(f"    {MET_JSON}")
    print(f"    {EVIDENCE_DIR}/")


if __name__ == "__main__":
    main()
