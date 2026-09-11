"""
pipeline_dissertation.py - Phase 2: security coverage of Matrix ecosystem forks
==================================================================================
Runs the layered verification over every fork and answers the two research questions:

  RQ1: How reliable is the automatic verification? (precision/recall/F1/Kappa,
       measured by ground_truth.py over the records produced here)
  RQ2: How much of the upstream CVE set is detected as fixed in each fork?
       (coverage per fork and per ecosystem category)

What it does:
  - Processes ALL CVEs of each upstream (not a hand-picked subset)
  - Selects the TOP 3 most active DIVERGENT forks per upstream (ahead_by > 0,
    measured through the compare API, not merely "most recent push")
  - Aggregates security coverage per fork: how many CVEs are patched?
  - Emits a consolidated report per Matrix ecosystem category

The layers:
  L1   literal content comparison. layer1_sha() evaluates
       `upstream_post == fork_content`; NOTHING IS HASHED - the function name is
       historical and is scheduled to be renamed (see REVIEW_RESPONSE_AND_ROADMAP.md).
  L2A  normalised AST + edit distance against the POST-patch reference only.
  L2B  dual reference: similarity to POST minus similarity to PRE (delta). This is
       what catches patches that REMOVE code, where L2A alone is blind.

Evidence selection: for each fix commit the highest-churn PRODUCTION file AND the
highest-churn TEST file are both evaluated, and their verdicts are unioned (a fix and
its regression test usually travel together). NOTE: until 2026-08-31 a deduplication
bug silently dropped the test-file record; impacto_evidencia_teste.py measures what
that cost, and every result folder dated before 2026-08-31_v2 carries the bug.

Aggregation rule: a (upstream, fork, CVE) triple counts as patched if it matches the
post-patch reference of ANY fix commit of that CVE (backports/cherry-picks count).

Optional decision rule (--regra-ab, OFF by default so the original methodology is
preserved): two guards that refuse a doubtful CORRIGIDO instead of inverting it -
  A) L2A only counts as patched when delta >= 0 (the fork is not closer to PRE);
  B) L2B only decides when sim_2a >= SIM_MINIMA_2B (0.60), i.e. a delta measured
     between two very distant files is treated as noise.
Refused verdicts fall into the uncertainty zone and escalate to human audit.

Usage:
    python pipeline_dissertation.py --token YOUR_TOKEN
    python pipeline_dissertation.py --token YOUR_TOKEN --upstream element-hq/synapse
    python pipeline_dissertation.py --token YOUR_TOKEN --top 5
    python pipeline_dissertation.py --token YOUR_TOKEN --fresh    # recompute from scratch
    python pipeline_dissertation.py --token YOUR_TOKEN --regra-ab # A+B variant
    python pipeline_dissertation.py --token YOUR_TOKEN --outdir resultados_YYYY-MM-DD

Outputs (verdict labels stay in Portuguese - see the glossary in README.md):
    dissertation_resultados.json     -- one record per fork/CVE/file
    dissertation_resultados.csv      -- flat table for analysis
    dissertation_cobertura.json      -- coverage per fork (% of CVEs patched)
    dissertation_metricas.json       -- metrics aggregated per category and overall
    evidencias_dissertacao/          -- every file actually compared, for offline audit
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Windows: o console usa cp1252 e quebra ao imprimir '→', '✓', etc. Forçar UTF-8
# nos streams antes de configurar o logging (o StreamHandler captura o stderr
# atual no momento do basicConfig).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests

# ─── Importar núcleo compartilhado ───────────────────────────────────────────
from pipeline_core import (
    parse_code, levenshtein, compute_sim,
    classify, classify_dual,
    ZSS_NODE_LIMIT, THRESHOLD_HIGH, THRESHOLD_LOW, MARGIN_ZI,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Constantes ──────────────────────────────────────────────────────────────
TARGET_CSV      = "target_dissertation.csv"
FIX_COMMITS_CSV = "cves-fixing-commits-dataset.csv"
OUT_JSON        = "dissertation_resultados.json"    # linhas cruas (1 por commit×fork)
OUT_CSV         = "dissertation_resultados.csv"
VER_JSON        = "dissertation_veredictos.json"     # 1 veredito agregado por (fork, cve)
COV_JSON        = "dissertation_cobertura.json"
MET_JSON        = "dissertation_metricas.json"
EVIDENCE_DIR    = "evidencias_dissertacao"
TOP_FORKS        = 3     # top N forks por upstream
DAYS_WINDOW      = 730   # forks ativos nos últimos N dias
MAX_FORKS_API    = 300   # limite de forks paginados pela API
API_DELAY        = 0.3   # delay entre chamadas API (segundos)
FORK_PROBE_LIMIT = 80    # máx. de forks comparados (ahead/behind) por upstream
REGRA_AB         = False # ativado por --regra-ab (ver decidir_status)

# Mapeamento extensão → linguagem de PARSING (nome do parser em pipeline_core).
# .tsx usa o parser TSX (superset com JSX); .ts usa o parser TypeScript puro.
EXT_LANG = {
    ".py": "python", ".rs": "rust", ".go": "go",
    ".kt": "kotlin", ".swift": "swift",
    ".ts": "typescript", ".tsx": "tsx",
    ".js": "javascript", ".java": "java",
}

# Linguagens (parsers) suportadas pela Camada 2 (AST) do pipeline_core.
# TypeScript/TSX cobrem client (element-web) e integration (matrix-hookshot);
# Go cobre bridge (mautrix/go).
SUPPORTED_LANGS = {"python", "rust", "kotlin", "swift", "typescript", "tsx", "go"}

# Extensões-fonte aceitáveis conforme a linguagem DECLARADA do upstream.
# Ex.: um upstream "typescript" pode ter o patch em .ts OU .tsx (element-web é
# React e altera muitos .tsx). A linguagem de parsing real é decidida por arquivo
# via EXT_LANG (o .tsx é parseado com o parser TSX).
LANG_EXTS = {
    "python":     {".py"},
    "rust":       {".rs"},
    "kotlin":     {".kt"},
    "swift":      {".swift"},
    "typescript": {".ts", ".tsx"},
    "tsx":        {".ts", ".tsx"},
    "go":         {".go"},
}


# ─── GitHub API ──────────────────────────────────────────────────────────────
class GitHubAPI:
    BASE = "https://api.github.com"

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def get(self, path: str, params: dict = None) -> dict | list | None:
        url = f"{self.BASE}/{path.lstrip('/')}"
        for attempt in range(3):
            try:
                r = self.session.get(url, params=params, timeout=30)
                if r.status_code == 403:
                    reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                    wait = max(reset - time.time(), 1)
                    log.warning(f"Rate limit. Aguardando {wait:.0f}s...")
                    time.sleep(wait)
                    continue
                if r.status_code == 404:
                    return None
                r.raise_for_status()
                time.sleep(API_DELAY)
                return r.json()
            except Exception as e:
                log.warning(f"Erro na tentativa {attempt+1}: {e}")
                time.sleep(2 ** attempt)
        return None

    def get_file(self, owner: str, repo: str, path: str, ref: str) -> str | None:
        data = self.get(f"repos/{owner}/{repo}/contents/{path}", {"ref": ref})
        if not data or "content" not in data:
            return None
        import base64
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    def get_commit_files(self, owner: str, repo: str, sha: str) -> list:
        data = self.get(f"repos/{owner}/{repo}/commits/{sha}")
        if not data:
            return []
        return data.get("files", [])

    def get_forks(self, owner: str, repo: str) -> list:
        forks, page = [], 1
        cutoff = datetime.now(timezone.utc).timestamp() - DAYS_WINDOW * 86400
        while len(forks) < MAX_FORKS_API:
            data = self.get(
                f"repos/{owner}/{repo}/forks",
                {"sort": "newest", "per_page": 100, "page": page}
            )
            if not data:
                break
            for f in data:
                pushed = f.get("pushed_at", "")
                if pushed:
                    ts = datetime.fromisoformat(pushed.replace("Z", "+00:00")).timestamp()
                    if ts >= cutoff:
                        forks.append(f)
            if len(data) < 100:
                break
            page += 1
        return forks


# Diretórios e sufixos de nome que identificam arquivos de TESTE (não a correção).
_TEST_DIRS  = {"test", "tests", "__tests__", "e2e", "spec", "specs",
              "unit-tests", "integration-tests", "testing"}
_TEST_FNAME = (".test.", ".spec.", "-test.", "_test.", "-spec.", "_spec.")


def is_test_file(path: str) -> bool:
    """
    True se o arquivo é de teste. Cobre:
      - qualquer segmento de diretório de teste (test/, tests/, e2e/, ... —
        inclusive no início do caminho, ex.: 'test/unit-tests/...');
      - 'playwright' em qualquer lugar do caminho;
      - nomes de arquivo com sufixo de teste (Foo-test.ts, foo.spec.tsx, ...)
        ou prefixo test_ (test_foo.py).
    """
    p = path.lower()
    if "playwright" in p:
        return True
    segments = p.split("/")
    if any(seg in _TEST_DIRS for seg in segments[:-1]):
        return True
    fn = segments[-1]
    return fn.startswith("test_") or any(m in fn for m in _TEST_FNAME)


_NON_SOURCE = (".md", ".toml", ".gradle", ".lock", "Cargo.lock",
               "package-lock", "yarn.lock", "CHANGELOG", ".json",
               ".yaml", ".yml", ".cfg", ".ini", ".txt")


# ─── Seleção dos arquivos representativos do patch ───────────────────────────
def select_patch_files(files: list, lang: str) -> list:
    """
    Seleciona os arquivos-fonte que representam a correção de segurança: o
    arquivo de PRODUÇÃO de maior churn e o arquivo de TESTE de maior churn,
    quando existirem.

    Avaliar ambos e unir os vereditos (na camada de agregação) é mais fiel à
    pergunta "o fork recebeu a correção?": a correção e o seu teste costumam
    andar juntos, mas qualquer um dos dois é evidência de que o patch chegou.
    O arquivo de produção é o principal (vem primeiro na lista).

    Retorna de 0 a 2 dicts de arquivo (produção primeiro). A linguagem de
    parsing real é derivada da extensão pelo chamador (EXT_LANG).
    """
    exts = LANG_EXTS.get(lang)
    if not exts:
        return []

    def has_ext(fn: str) -> bool:
        return any(fn.endswith(e) for e in exts)

    def churn(f) -> int:
        return f.get("additions", 0) + f.get("deletions", 0)

    base = [
        f for f in files
        if has_ext(f.get("filename", ""))
        and f.get("status") in ("modified", "renamed", "added")
        and not any(x in f.get("filename", "") for x in _NON_SOURCE)
    ]
    if not base:
        return []

    prod = [f for f in base if not is_test_file(f.get("filename", ""))]
    test = [f for f in base if is_test_file(f.get("filename", ""))]

    chosen = []
    if prod:
        chosen.append(max(prod, key=churn))   # produção primeiro (principal)
    if test:
        chosen.append(max(test, key=churn))   # teste como evidência adicional
    return chosen


def select_patch_file(files: list, lang: str) -> dict | None:
    """Compatibilidade: retorna só o arquivo principal (produção preferida)."""
    fs = select_patch_files(files, lang)
    return fs[0] if fs else None


# ─── Verificação Camada 1: SHA ────────────────────────────────────────────────
def layer1_sha(upstream_post: str, fork_content: str) -> bool:
    return upstream_post == fork_content


# ─── Verificação Camada 2A: AST + Levenshtein ────────────────────────────────
def layer2a(upstream_post: str, fork_content: str, lang: str) -> tuple:
    """Retorna (sim, label, method)."""
    ast_up = parse_code(upstream_post, lang)
    ast_fk = parse_code(fork_content, lang)
    if ast_up is None or ast_fk is None:
        return None, "UNSUPPORTED", "no_ast"
    sim_lev, sim_zss, sim_comb, method = compute_sim(ast_up, ast_fk)
    label = classify(sim_comb)
    return sim_comb, label, method


# ─── Verificação Camada 2B: Referência Dupla ─────────────────────────────────
def layer2b(upstream_pre: str, upstream_post: str, fork_content: str, lang: str) -> tuple:
    """Retorna (sim_patch, sim_vuln, delta, label_2b)."""
    ast_pre  = parse_code(upstream_pre,  lang)
    ast_post = parse_code(upstream_post, lang)
    ast_fk   = parse_code(fork_content,  lang)
    if None in (ast_pre, ast_post, ast_fk):
        return None, None, None, "UNSUPPORTED"
    sim_patch, _, _, _ = compute_sim(ast_post, ast_fk)
    sim_vuln,  _, _, _ = compute_sim(ast_pre,  ast_fk)
    label, delta = classify_dual(sim_patch, sim_vuln)
    return sim_patch, sim_vuln, delta, label


# ─── Salvar evidência ─────────────────────────────────────────────────────────
def save_evidence(cve_id: str, label: str, content: str):
    d = Path(EVIDENCE_DIR) / cve_id.replace("/", "_")
    d.mkdir(parents=True, exist_ok=True)
    (d / label).write_text(content, encoding="utf-8")


# ─── Carregar targets e fix commits ──────────────────────────────────────────
def load_targets() -> list:
    with open(TARGET_CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter=";"))


def load_fix_commits() -> dict:
    """Retorna dict: (owner, repo) → [{"id", "commit_sha", "commit_url", ...}]"""
    result = {}
    if not Path(FIX_COMMITS_CSV).exists():
        log.warning(f"{FIX_COMMITS_CSV} não encontrado. Execute pipeline.py primeiro.")
        return result
    with open(FIX_COMMITS_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter=";"):
            key = (row.get("github_owner", ""), row.get("github_repo", ""))
            result.setdefault(key, []).append(row)
    return result


# ─── Seleção dos forks-alvo ──────────────────────────────────────────────────
def _pushed_ts(f) -> float:
    p = f.get("pushed_at", "")
    if not p:
        return 0.0
    return datetime.fromisoformat(p.replace("Z", "+00:00")).timestamp()


def select_top_forks(api: "GitHubAPI", owner: str, repo: str,
                     forks: list, n: int = TOP_FORKS,
                     probe_limit: int = FORK_PROBE_LIMIT) -> list:
    """
    Seleciona os N forks mais ativos que DIVERGIRAM do upstream, isto é, que têm
    commits próprios (ahead_by > 0 no compare contra o upstream).

    Por quê: a pergunta de pesquisa é sobre forks DIVERGENTES que propagam (ou
    não) patches de segurança. Ordenar só por "push mais recente" seleciona,
    em repositórios muito populares (element-web), forks triviais/abandonados
    que sequer contêm os arquivos (→ FILE_NOT_FOUND). Exigir ahead_by > 0 define
    corretamente a população de estudo e evita esse ruído.

    Percorre os forks por recência, faz no máx. `probe_limit` chamadas de compare
    e para ao achar N divergentes. Fallback: se nenhum divergente for encontrado,
    usa os N mais recentes (comportamento antigo).
    """
    ranked = sorted(forks, key=_pushed_ts, reverse=True)

    up = api.get(f"repos/{owner}/{repo}")
    base_branch = (up or {}).get("default_branch", "main")

    selected, probed = [], 0
    for f in ranked:
        if len(selected) >= n or probed >= probe_limit:
            break
        fo = f["owner"]["login"]
        fr = f["name"]
        fb = f.get("default_branch") or "main"
        probed += 1
        cmp = api.get(f"repos/{owner}/{repo}/compare/{base_branch}...{fo}:{fb}")
        ahead  = (cmp or {}).get("ahead_by", 0) or 0
        behind = (cmp or {}).get("behind_by", 0) or 0
        if ahead > 0:
            f["_ahead_by"], f["_behind_by"] = ahead, behind
            selected.append(f)
            log.info(f"    fork divergente: {fo}/{fr} (ahead={ahead}, behind={behind})")

    if not selected:
        log.warning(f"    Nenhum fork divergente em {probed} testados; "
                    f"usando os {n} mais recentes.")
        selected = ranked[:n]
    return selected


# ─── Processar um upstream ────────────────────────────────────────────────────
def process_upstream(api: GitHubAPI, target: dict, fix_commits: list, top_n: int = TOP_FORKS) -> list:
    owner    = target["github_owner"]
    repo     = target["github_repo"]
    category = target["category"]
    lang     = target["language"].lower()

    if lang not in SUPPORTED_LANGS:
        log.warning(f"  Linguagem '{lang}' não suportada pelo parser AST. Pulando {owner}/{repo}.")
        return []

    log.info(f"\n{'='*60}")
    log.info(f"Upstream: {owner}/{repo} [{category}] ({lang})")
    log.info(f"CVEs a verificar: {len(fix_commits)}")

    # ── Selecionar forks divergentes mais ativos ────────────────────────────
    log.info("  Coletando forks...")
    all_forks = api.get_forks(owner, repo)
    top_forks = select_top_forks(api, owner, repo, all_forks, top_n)
    log.info(f"  Forks ativos: {len(all_forks)} → {len(top_forks)} selecionados (divergentes)")

    if not top_forks:
        log.warning(f"  Nenhum fork ativo encontrado para {owner}/{repo}.")
        return []

    results = []

    # ── Para cada CVE com fix commit ────────────────────────────────────────
    for fix in fix_commits:
        cve_id  = fix.get("id", "")
        fix_sha = fix.get("commit_sha", "")
        if not fix_sha or fix_sha.lower() in ("", "nan", "none", "not found"):
            log.info(f"  [{cve_id}] Sem fix commit — pulando.")
            continue

        log.info(f"  [{cve_id}] fix={fix_sha[:8]}")

        # Extrair arquivos do commit
        files = api.get_commit_files(owner, repo, fix_sha)
        if not files:
            log.warning(f"  [{cve_id}] Não foi possível obter arquivos do commit.")
            continue

        # Arquivos representativos: produção + teste (avaliados e unidos depois)
        patch_files = select_patch_files(files, lang)
        if not patch_files:
            log.warning(f"  [{cve_id}] Nenhum arquivo-alvo encontrado no commit.")
            continue

        # Parent commit (pré-patch) — obtido uma vez por fix commit
        commit_data = api.get(f"repos/{owner}/{repo}/commits/{fix_sha}")
        parents = (commit_data or {}).get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None

        # ── Para cada arquivo representativo (produção e/ou teste) ──────────
        for pf in patch_files:
            filepath = pf["filename"]
            churn    = pf.get("additions", 0) + pf.get("deletions", 0)
            role     = "teste" if is_test_file(filepath) else "produção"
            # Linguagem de parsing derivada da extensão real (ex.: .tsx → TSX).
            ext       = os.path.splitext(filepath)[1].lower()
            file_lang = EXT_LANG.get(ext, lang)
            log.info(f"    Arquivo [{role}]: {filepath} (churn={churn}, parser={file_lang})")

            upstream_post = api.get_file(owner, repo, filepath, fix_sha)
            if upstream_post is None:
                log.warning(f"    Não foi possível baixar pós-patch de {filepath}.")
                continue
            upstream_pre = api.get_file(owner, repo, filepath, parent_sha) if parent_sha else None

            if upstream_pre:
                save_evidence(cve_id, f"upstream_pre_{filepath.replace('/', '_')}", upstream_pre)
            save_evidence(cve_id, f"upstream_post_{filepath.replace('/', '_')}", upstream_post)

            # ── Para cada fork ──────────────────────────────────────────────
            for fork in top_forks:
                fork_owner = fork["owner"]["login"]
                fork_repo  = fork["name"]
                fork_full  = f"{fork_owner}/{fork_repo}"
                fork_push  = fork.get("pushed_at", "")

                fork_content = api.get_file(fork_owner, fork_repo, filepath, "HEAD")
                if fork_content is None:
                    log.info(f"    {fork_full}: arquivo não encontrado no fork.")
                    results.append(_build_row(
                        owner, repo, category, lang, cve_id, fix_sha, filepath,
                        churn, fork_full, fork_push,
                        sha_match=False, status="FILE_NOT_FOUND",
                        sim_2a=None, label_2a="FILE_NOT_FOUND",
                        sim_patch=None, sim_vuln=None, delta=None, label_2b="FILE_NOT_FOUND"
                    ))
                    continue

                save_evidence(cve_id, f"fork_{fork_owner}_{fork_repo}_{filepath.replace('/', '_')}", fork_content)

                # Camada 1
                if layer1_sha(upstream_post, fork_content):
                    results.append(_build_row(
                        owner, repo, category, lang, cve_id, fix_sha, filepath,
                        churn, fork_full, fork_push,
                        sha_match=True, status="CORRIGIDO",
                        sim_2a=1.0, label_2a="CORRIGIDO",
                        sim_patch=1.0, sim_vuln=None, delta=None, label_2b="CORRIGIDO"
                    ))
                    log.info(f"    {fork_full} [{role}]: L1 SHA=OK → CORRIGIDO")
                    continue

                # Camada 2A
                sim_2a, label_2a, method = layer2a(upstream_post, fork_content, file_lang)

                # Camada 2B (se pré-patch disponível)
                if upstream_pre:
                    sim_patch, sim_vuln, delta, label_2b = layer2b(
                        upstream_pre, upstream_post, fork_content, file_lang
                    )
                else:
                    sim_patch, sim_vuln, delta, label_2b = None, None, None, "NO_PRE_PATCH"

                # Status final: preferir 2B quando disponível e conclusivo
                # (com --regra-ab, ver decidir_status/SIM_MINIMA_2B)
                status = decidir_status(label_2a, label_2b, sim_2a, delta, REGRA_AB)

                sim_str   = f"{sim_2a:.3f}" if sim_2a is not None else "N/A"
                delta_str = f"{delta:.3f}"  if delta  is not None else "N/A"
                log.info(f"    {fork_full} [{role}]: L2A={sim_str} L2B δ={delta_str} → {status}")

                results.append(_build_row(
                    owner, repo, category, lang, cve_id, fix_sha, filepath,
                    churn, fork_full, fork_push,
                    sha_match=False, status=status,
                    sim_2a=sim_2a, label_2a=label_2a,
                    sim_patch=sim_patch, sim_vuln=sim_vuln, delta=delta, label_2b=label_2b,
                    method=method
                ))

    return results


# ─── Regra A+B (opcional, --regra-ab) ────────────────────────────────────────
# Diagnostico do run 2026-08-17: nos 7 falsos positivos as duas camadas SEMPRE
# discordaram, e a decisao caiu no lado errado. Dois mecanismos:
#   A) 2A alta com delta NEGATIVO (arquivo-monolito: o patch e minusculo perto do
#      arquivo, sim_2a chega a 0,987 com o fork sem a correcao). O sinal certo
#      estava na 2B — o fork esta mais proximo do PRE-patch.
#   B) 2B decidindo na borda da margem em fork muito divergente (sim_2a 0,47-0,56,
#      delta 0,0516 contra margem 0,05): sem piso de similaridade absoluta, o
#      delta e ruido.
# A regra NAO inverte veredito: ela apenas RECUSA o "CORRIGIDO" nesses dois casos
# e manda o par para a zona de incerteza (auditoria humana).
SIM_MINIMA_2B = 0.60   # piso de similaridade absoluta para a 2B poder decidir


def decidir_status(label_2a, label_2b, sim_2a, delta, regra_ab: bool = False) -> str:
    """
    Combina os vereditos das camadas 2A e 2B em um status de linha.

    Padrao (metodologia original): a 2B tem prioridade quando conclusiva; senao
    vale a 2A; senao, zona de incerteza.

    Com regra_ab=True, dois guardas sao adicionados (ver comentario acima).
    """
    if regra_ab:
        # (B) 2B so decide CORRIGIDO com similaridade absoluta minima
        if label_2b == "CORRIGIDO" and (sim_2a is None or sim_2a < SIM_MINIMA_2B):
            return "ZONA_INCERTEZA"
        # (A) 2A so vale como CORRIGIDO se o fork nao estiver mais perto do pre-patch
        if (label_2b not in ("CORRIGIDO", "VULNERAVEL")
                and label_2a == "CORRIGIDO"
                and delta is not None and delta < 0):
            return "ZONA_INCERTEZA"

    if label_2b in ("CORRIGIDO", "VULNERAVEL"):
        return label_2b
    if label_2a in ("CORRIGIDO", "NAO_CORRIGIDO"):
        return label_2a
    return "ZONA_INCERTEZA"


def _build_row(owner, repo, category, lang, cve_id, fix_sha, filepath,
               churn, fork, fork_push, sha_match, status,
               sim_2a, label_2a, sim_patch, sim_vuln, delta, label_2b,
               method="lev_only") -> dict:
    return {
        "upstream":     f"{owner}/{repo}",
        "category":     category,
        "language":     lang,
        "cve_id":       cve_id,
        "fix_sha":      fix_sha,
        "filepath":     filepath,
        "churn":        churn,
        "fork":         fork,
        "fork_pushed":  fork_push,
        "sha_match":    sha_match,
        "status":       status,
        "sim_2a":       round(sim_2a, 4) if sim_2a is not None else None,
        "label_2a":     label_2a,
        "sim_patch":    round(sim_patch, 4) if sim_patch is not None else None,
        "sim_vuln":     round(sim_vuln, 4) if sim_vuln is not None else None,
        "delta":        round(delta, 4) if delta is not None else None,
        "label_2b":     label_2b,
        "method":       method,
        "ts":           datetime.now(timezone.utc).isoformat(),
    }


# ─── Agregação de múltiplos fix commits por CVE (regra da união) ─────────────
# Quando um CVE tem vários fix commits (backports/cherry-picks/follow-ups),
# avaliamos cada commit e colapsamos para UM veredito por (upstream, fork, cve):
#   • CORRIGIDO vence — o fork incorporou a correção de ALGUM dos commits;
#   • sem correção, a INCERTEZA domina VULNERAVEL, para escalar à auditoria
#     humana em vez de afirmar vulnerabilidade (Zona de Incerteza é feature);
#   • FILE_NOT_FOUND é o mais fraco (arquivo ausente em todos os commits).
_STATUS_PRIORITY = {
    "CORRIGIDO":       4,
    "ZONA_INCERTEZA":  3,
    "VULNERAVEL":      2,
    "NAO_CORRIGIDO":   2,
    "FILE_NOT_FOUND":  1,
}


def _best_status(statuses: list) -> str:
    return max(statuses, key=lambda s: _STATUS_PRIORITY.get(s, 0))


def aggregate_verdicts(results: list) -> list:
    """
    Colapsa as linhas cruas (uma por fix commit × fork) em UM veredito por
    (upstream, fork, cve_id), aplicando a regra da união entre fix commits.
    Preserva rastreabilidade: nº de commits e o status de cada sha.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for r in results:
        groups[(r["upstream"], r["fork"], r["cve_id"])].append(r)

    agg = []
    for (upstream, fork, cve), rows in groups.items():
        statuses = [r["status"] for r in rows]
        status   = _best_status(statuses)
        rep      = next(r for r in rows if r["status"] == status)  # linha representativa
        agg.append({
            "upstream":          upstream,
            "category":          rep["category"],
            "language":          rep["language"],
            "cve_id":            cve,
            "fork":              fork,
            "fork_pushed":       rep.get("fork_pushed", ""),
            "status":            status,
            "n_fix_commits":     len(rows),
            "fix_shas":          sorted({r["fix_sha"] for r in rows}),
            "status_por_commit": {r["fix_sha"]: r["status"] for r in rows},
        })
    return agg


# ─── Calcular cobertura por fork ─────────────────────────────────────────────
def compute_coverage(results: list) -> dict:
    """
    Para cada fork, calcula:
      - n_cves_total: CVEs do upstream com fix commit
      - n_corrigidas: CVEs com status CORRIGIDO
      - n_vulneraveis: CVEs com status VULNERAVEL
      - n_incertas: ZONA_INCERTEZA
      - cobertura_pct: n_corrigidas / n_cves_total * 100
    """
    coverage = {}
    for row in results:
        fork = row["fork"]
        upstream = row["upstream"]
        key = f"{upstream}::{fork}"
        if key not in coverage:
            coverage[key] = {
                "fork": fork,
                "upstream": upstream,
                "category": row["category"],
                "language": row["language"],
                "cves": {},
            }
        cve = row["cve_id"]
        # última classificação para esse CVE nesse fork
        coverage[key]["cves"][cve] = row["status"]

    # Agregar métricas
    report = []
    for key, data in coverage.items():
        statuses = list(data["cves"].values())
        n_total    = len(statuses)
        n_corr     = statuses.count("CORRIGIDO")
        n_vuln     = statuses.count("VULNERAVEL") + statuses.count("NAO_CORRIGIDO")
        n_incerta  = statuses.count("ZONA_INCERTEZA")
        n_sem_arq  = statuses.count("FILE_NOT_FOUND")
        cobertura  = (n_corr / n_total * 100) if n_total > 0 else 0

        report.append({
            "fork":            data["fork"],
            "upstream":        data["upstream"],
            "category":        data["category"],
            "language":        data["language"],
            "n_cves_total":    n_total,
            "n_corrigidas":    n_corr,
            "n_vulneraveis":   n_vuln,
            "n_zona_incerteza": n_incerta,
            "n_sem_arquivo":   n_sem_arq,
            "cobertura_pct":   round(cobertura, 1),
            "por_cve":         data["cves"],
        })

    return sorted(report, key=lambda x: x["cobertura_pct"], reverse=True)


# ─── Calcular métricas globais ────────────────────────────────────────────────
def compute_metrics(results: list, coverage: list) -> dict:
    from collections import defaultdict

    by_category = defaultdict(lambda: {
        "n_verificacoes": 0, "n_corrigidas": 0,
        "n_vulneraveis": 0, "n_incertas": 0,
        "cobertura_media_pct": 0
    })

    for row in results:
        cat = row["category"]
        by_category[cat]["n_verificacoes"] += 1
        if row["status"] == "CORRIGIDO":
            by_category[cat]["n_corrigidas"] += 1
        elif row["status"] in ("VULNERAVEL", "NAO_CORRIGIDO"):
            by_category[cat]["n_vulneraveis"] += 1
        elif row["status"] == "ZONA_INCERTEZA":
            by_category[cat]["n_incertas"] += 1

    # Cobertura média por categoria
    cov_by_cat = defaultdict(list)
    for c in coverage:
        cov_by_cat[c["category"]].append(c["cobertura_pct"])
    for cat, covs in cov_by_cat.items():
        by_category[cat]["cobertura_media_pct"] = round(sum(covs) / len(covs), 1)

    n_total = len(results)
    n_corr  = sum(1 for r in results if r["status"] == "CORRIGIDO")
    n_vuln  = sum(1 for r in results if r["status"] in ("VULNERAVEL", "NAO_CORRIGIDO"))
    n_inc   = sum(1 for r in results if r["status"] == "ZONA_INCERTEZA")

    return {
        "n_upstreams":       len({r["upstream"] for r in results}),
        "n_forks_total":     len({r["fork"] for r in results}),
        "n_cves_verificadas": len({r["cve_id"] for r in results}),
        "n_verificacoes":    n_total,
        "n_corrigidas":      n_corr,
        "n_vulneraveis":     n_vuln,
        "n_zona_incerteza":  n_inc,
        "cobertura_media_pct": round(
            sum(c["cobertura_pct"] for c in coverage) / len(coverage), 1
        ) if coverage else 0,
        "por_categoria": dict(by_category),
    }


# ─── Salvar resultados ────────────────────────────────────────────────────────
def save_results(results: list, verdicts: list, coverage: list, metrics: dict):
    # JSON completo — linhas cruas (uma por fix commit × fork, para auditoria)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    log.info(f"  Salvo: {OUT_JSON}")

    # CSV flat (linhas cruas)
    if results:
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys(), delimiter=";")
            writer.writeheader()
            writer.writerows(results)
        log.info(f"  Salvo: {OUT_CSV}")

    # Veredictos agregados (um por fork × CVE, união entre fix commits)
    with open(VER_JSON, "w", encoding="utf-8") as f:
        json.dump(verdicts, f, indent=2, ensure_ascii=False)
    log.info(f"  Salvo: {VER_JSON}")

    # Cobertura por fork
    with open(COV_JSON, "w", encoding="utf-8") as f:
        json.dump(coverage, f, indent=2, ensure_ascii=False)
    log.info(f"  Salvo: {COV_JSON}")

    # Métricas globais
    with open(MET_JSON, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    log.info(f"  Salvo: {MET_JSON}")


# ─── Carregar resultados anteriores (acumulação) ─────────────────────────────
def load_existing() -> list:
    if Path(OUT_JSON).exists():
        with open(OUT_JSON, encoding="utf-8") as f:
            return json.load(f)
    return []


def already_processed(existing: list, upstream: str, cve_id: str,
                      fork: str, fix_sha: str, filepath: str) -> bool:
    # A chave inclui fix_sha: um CVE com vários fix commits (backports/
    # follow-ups) é avaliado por commit, não colapsado no primeiro.
    # A chave TAMBÉM inclui filepath: select_patch_files() devolve o arquivo de
    # produção e o de teste do mesmo commit, e sem o filepath a linha de teste
    # era descartada como "já processada" — a união produção+teste descrita na
    # metodologia nunca chegava a acontecer (corrigido em 2026-08-31).
    return any(
        r["upstream"] == upstream and r["cve_id"] == cve_id
        and r["fork"] == fork and r.get("fix_sha") == fix_sha
        and r.get("filepath") == filepath
        for r in existing
    )


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Pipeline Dissertação — Cobertura de Segurança")
    parser.add_argument("--token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("--upstream", default=None,
                        help="Filtrar por upstream específico (ex: element-hq/synapse)")
    parser.add_argument("--top", type=int, default=TOP_FORKS,
                        help=f"Número de forks por upstream (padrão: {TOP_FORKS})")
    parser.add_argument("--regra-ab", action="store_true",
                        help="ativa os guardas A (2A so vale com delta >= 0) e "
                             "B (2B so decide com sim_2a >= SIM_MINIMA_2B): recusa "
                             "o CORRIGIDO duvidoso e manda para a zona de incerteza")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignora resultados anteriores e recalcula tudo do zero "
                             "(use após mudanças de metodologia)")
    parser.add_argument("--outdir", default=None,
                        help="Diretório de saída (padrão: CWD). Os arquivos de "
                             "entrada continuam sendo lidos do CWD; só as saídas "
                             "(JSON/CSV/evidências) vão para o outdir. Útil para "
                             "separar execuções por data sem misturar resultados.")
    args = parser.parse_args()

    global REGRA_AB
    REGRA_AB = args.regra_ab
    if REGRA_AB:
        log.info(f"Regra A+B ATIVA (sim minima da 2B = {SIM_MINIMA_2B})")

    top_n = args.top

    api = GitHubAPI(args.token)
    targets = load_targets()
    fix_commits_all = load_fix_commits()
    existing = [] if args.fresh else load_existing()
    if args.fresh:
        log.info("Modo --fresh: ignorando resultados anteriores.")

    if args.upstream:
        parts = args.upstream.split("/")
        targets = [t for t in targets
                   if t["github_owner"] == parts[0] and t["github_repo"] == parts[1]]
        if not targets:
            log.error(f"Upstream '{args.upstream}' não encontrado em {TARGET_CSV}.")
            return

    log.info(f"Upstreams a processar: {len(targets)}")
    log.info(f"Top forks por upstream: {top_n}")

    # Entradas já foram lidas do CWD acima. A partir daqui, todas as SAÍDAS
    # (save_results, save_evidence) usam caminhos relativos, então mudar o CWD
    # para o outdir isola os resultados desta execução.
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        os.chdir(args.outdir)
        log.info(f"Saída isolada em: {args.outdir}")

    all_results = list(existing)

    for target in targets:
        owner = target["github_owner"]
        repo  = target["github_repo"]
        key   = (owner, repo)

        fix_commits = fix_commits_all.get(key, [])
        if not fix_commits:
            log.warning(f"Sem fix commits para {owner}/{repo}. Execute pipeline.py primeiro.")
            continue

        # Filtrar já processados (chave inclui fix_sha → múltiplos commits/CVE)
        new_results = process_upstream(api, target, fix_commits, top_n)
        for row in new_results:
            if not already_processed(all_results, row["upstream"], row["cve_id"],
                                     row["fork"], row["fix_sha"], row["filepath"]):
                all_results.append(row)

    if not all_results:
        log.warning("Nenhum resultado gerado.")
        return

    # Agregar múltiplos fix commits por CVE → um veredito por (fork, CVE)
    verdicts = aggregate_verdicts(all_results)
    coverage = compute_coverage(verdicts)
    metrics  = compute_metrics(verdicts, coverage)
    save_results(all_results, verdicts, coverage, metrics)

    # ── Imprimir resumo no terminal ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("RESUMO — Cobertura de Segurança por Fork")
    print("=" * 60)
    for c in coverage:
        print(f"  {c['fork']:<45} {c['cobertura_pct']:5.1f}%  "
              f"({c['n_corrigidas']}/{c['n_cves_total']} CVEs corrigidas)  "
              f"[{c['category']}]")

    print("\n" + "=" * 60)
    print("MÉTRICAS GLOBAIS")
    print("=" * 60)
    print(f"  Upstreams:            {metrics['n_upstreams']}")
    print(f"  Forks verificados:    {metrics['n_forks_total']}")
    print(f"  CVEs verificadas:     {metrics['n_cves_verificadas']}")
    print(f"  Verificações totais:  {metrics['n_verificacoes']}")
    print(f"  Corrigidas:           {metrics['n_corrigidas']}")
    print(f"  Vulneráveis:          {metrics['n_vulneraveis']}")
    print(f"  Zona de Incerteza:    {metrics['n_zona_incerteza']}")
    print(f"  Cobertura média:      {metrics['cobertura_media_pct']}%")
    print("\nPor categoria:")
    for cat, m in metrics["por_categoria"].items():
        print(f"  {cat:<15} cobertura média: {m['cobertura_media_pct']}%  "
              f"({m['n_corrigidas']} corrigidas / {m['n_verificacoes']} verificações)")
    print()


if __name__ == "__main__":
    main()