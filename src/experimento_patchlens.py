"""
experimento_patchlens.py — nossa metodologia aplicada ao dataset do PatchLens
=============================================================================
PatchLens (Paixao et al., FSE 2026) publica `final_dataset.csv`: 1.405 pares
(CVE, commit de correção, VIC) de Linux, FFmpeg e PHP, todos em C. O dataset não
tem forks — responde "QUAIS VARIANTES DE COMPILAÇÃO tinham a falha", não "QUEM
recebeu a correção". Para aplicar a nossa pergunta, os "forks" são os RAMOS DE
MANUTENÇÃO de cada produto: derivados divergentes do upstream, com backport
manual — o mesmo fenômeno que estudamos no Matrix, em escala de ecossistema C.

  Linux   gregkh/linux   linux-4.19.y 5.4.y 5.10.y 5.15.y 6.1.y 6.6.y
  FFmpeg  FFmpeg/FFmpeg  release/4.4 5.1 6.0 6.1 7.0 7.1
  PHP     php/php-src    PHP-7.4 8.0 8.1 8.2 8.3 8.4

Ganho em relação ao estudo Matrix: um ORÁCULO DE PROVENIÊNCIA independente do
código. Para cada (ramo, commit de correção), pelo histórico git:
  HERANCA      o fix é ancestral do ponto de ramificação — o ramo nasceu corrigido
  MERGE        o fix é ancestral da ponta, mas não do ponto de ramificação
               (modelo merge-up do PHP)
  BACKPORT     um commit do ramo cita o SHA do fix ("commit X upstream",
               "[ Upstream commit X ]", "cherry picked from commit X")
  SEM_CORRECAO nenhuma das anteriores
O oráculo automático por linhas do `ground_truth.py` também é calculado sobre o
mesmo arquivo, para comparar os dois oráculos.

A verificação é a do `pipeline_dissertation.py`, importada, não reescrita:
select_patch_files → Camada 1 → 2A → 2B → decidir_status (união e Regra A+B) →
agregação por união entre commits do mesmo CVE. Os arquivos são baixados no SHA
da ponta de cada ramo, fixado no início (snapshot congelado).

Uso:
  python experimento_patchlens.py oraculo   [--produto linux]
  python experimento_patchlens.py verificar [--produto linux] [--amostra 50] [--workers 8]
  python experimento_patchlens.py metricas
"""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from difflib import SequenceMatcher
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests

import pipeline_dissertation as pd
from pipeline_core import parse_code, compute_sim, classify, classify_dual

pd.LANG_EXTS["c"] = {".c", ".h"}
pd.EXT_LANG.update({".c": "c", ".h": "c"})

AQUI      = Path(__file__).resolve().parent
DATASET   = AQUI.parent / "dados" / "patchlens" / "final_dataset.csv"
REPOS     = Path(os.environ.get("PATCHLENS_REPOS", "patchlens_repos"))
CACHE_RAW = REPOS / "cache_raw"
CACHE_API = REPOS / "cache_api"
OUT       = AQUI.parent / "resultados" / "validacao_externa"

PRODUTOS = {
    "linux/linux_kernel": {
        "nome": "linux", "git": "linux.git", "master": "master",
        "repo_fix": "torvalds/linux", "repo_ramo": "gregkh/linux",
        "ramos": ["linux-4.19.y", "linux-5.4.y", "linux-5.10.y",
                  "linux-5.15.y", "linux-6.1.y", "linux-6.6.y"],
    },
    "ffmpeg/ffmpeg": {
        "nome": "ffmpeg", "git": "ffmpeg.git", "master": "master",
        "repo_fix": "FFmpeg/FFmpeg", "repo_ramo": "FFmpeg/FFmpeg",
        "ramos": ["release/4.4", "release/5.1", "release/6.0",
                  "release/6.1", "release/7.0", "release/7.1"],
    },
    "php/php": {
        "nome": "php", "git": "php.git", "master": "master",
        "repo_fix": "php/php-src", "repo_ramo": "php/php-src",
        "ramos": ["PHP-7.4", "PHP-8.0", "PHP-8.1", "PHP-8.2", "PHP-8.3", "PHP-8.4"],
    },
}
POR_NOME = {v["nome"]: k for k, v in PRODUTOS.items()}

# Citações explícitas de backport. "Fixes: <sha>" fica de fora de propósito: aponta
# o commit que INTRODUZIU um bug, não o que foi trazido para o ramo.
RE_BACKPORT = re.compile(
    r"(?:commit\s+([0-9a-f]{12,40})\s+upstream"
    r"|upstream\s+commit:?\s+([0-9a-f]{12,40})"
    r"|cherry[- ]picked\s+from\s+commit\s+([0-9a-f]{12,40})"
    r"|backport(?:ed)?\s+(?:of|from)\s+(?:commit\s+)?([0-9a-f]{12,40}))",
    re.IGNORECASE,
)


# ─── utilidades ──────────────────────────────────────────────────────────────
def git(prod: dict, *args) -> str:
    r = subprocess.run(["git", "-C", str(REPOS / prod["git"]), *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode not in (0, 1):
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:200]}")
    return r.stdout if r.returncode == 0 else ""


def is_ancestor(prod, a, b) -> bool:
    r = subprocess.run(["git", "-C", str(REPOS / prod["git"]),
                        "merge-base", "--is-ancestor", a, b], capture_output=True)
    return r.returncode == 0


def carregar_dataset(produto: str | None = None) -> list:
    rows = list(csv.DictReader(open(DATASET, encoding="utf-8")))
    if produto:
        rows = [r for r in rows if r["product"] == POR_NOME[produto]]
    return rows


def token() -> str:
    for line in open(AQUI / ".env", encoding="utf-8"):
        k, _, v = line.partition("=")
        if k.strip() in ("GITHUB_TOKEN", "GH_TOKEN", "TOKEN"):
            return v.strip().strip('"')
    raise SystemExit("token GitHub ausente no .env")


# ─── fase 1: oráculo de proveniência (só git, sem rede) ──────────────────────
def indice_backports(prod, ramo) -> dict:
    """Prefixo de 12 caracteres do SHA citado → commit do ramo que o cita."""
    out = git(prod, "log", "--format=%H%x1f%B%x1e", f"{prod['master']}..{ramo}")
    idx = {}
    for bloco in out.split("\x1e"):
        if "\x1f" not in bloco:
            continue
        h, msg = bloco.split("\x1f", 1)
        for m in RE_BACKPORT.finditer(msg):
            sha = next(g for g in m.groups() if g)
            idx.setdefault(sha[:12].lower(), h.strip())
    return idx


def fase_oraculo(args):
    OUT.mkdir(exist_ok=True)
    rows = carregar_dataset(args.produto)
    saida = []
    for pkey, prod in PRODUTOS.items():
        sub = [r for r in rows if r["product"] == pkey]
        if not sub:
            continue
        print(f"\n[{prod['nome']}] {len(sub)} linhas do dataset")
        pontas, pontos, idx = {}, {}, {}
        for ramo in prod["ramos"]:
            pontas[ramo] = git(prod, "rev-parse", ramo).strip()
            pontos[ramo] = git(prod, "merge-base", ramo, prod["master"]).strip()
            idx[ramo] = indice_backports(prod, ramo)
            print(f"  {ramo:<14} ponta {pontas[ramo][:10]}  ramificação {pontos[ramo][:10]}"
                  f"  {len(idx[ramo])} citações de backport")
        for r in sub:
            sha = r["id"].lower()
            existe = bool(git(prod, "cat-file", "-t", sha).strip())
            data = git(prod, "log", "-1", "--format=%cs", sha).strip() if existe else ""
            # fix fora da linha principal (no FFmpeg, commits só em ramos de release; no PHP,
            # ramos antigos):
            # aí a ausência de proveniência não diz nada sobre o ramo
            no_master = existe and is_ancestor(prod, sha, prod["master"])
            for ramo in prod["ramos"]:
                if not existe:
                    rot, bp = "INACESSIVEL", ""
                elif is_ancestor(prod, sha, pontos[ramo]):
                    rot, bp = "HERANCA", ""
                elif is_ancestor(prod, sha, pontas[ramo]):
                    rot, bp = "MERGE", ""
                elif sha[:12] in idx[ramo]:
                    rot, bp = "BACKPORT", idx[ramo][sha[:12]]
                else:
                    rot, bp = "SEM_CORRECAO", ""
                saida.append({
                    "produto": prod["nome"], "cve": r["cve_id"], "fix_sha": sha,
                    "fix_data": data, "vic": r["flag"], "ramo": ramo,
                    "ponta": pontas[ramo], "proveniencia": rot, "backport_sha": bp,
                    "fix_no_master": no_master,
                })
        c = Counter(s["proveniencia"] for s in saida if s["produto"] == prod["nome"])
        print(f"  proveniência: {dict(c)}")
    alvo = OUT / "oraculo_proveniencia.json"
    if args.produto and alvo.exists():   # preserva os outros produtos
        antigos = [x for x in json.load(open(alvo, encoding="utf-8"))
                   if x["produto"] != args.produto]
        saida = antigos + saida
    json.dump(saida, open(alvo, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\n→ {alvo} ({len(saida)} pares ramo×commit)")


# ─── fase 2: verificação estrutural (rede + AST) ─────────────────────────────
_SESS = None


def sess():
    global _SESS
    if _SESS is None:
        _SESS = requests.Session()
        _SESS.headers["Authorization"] = f"token {token()}"
    return _SESS


def commit_api(repo: str, sha: str) -> dict | None:
    CACHE_API.mkdir(parents=True, exist_ok=True)
    f = CACHE_API / f"{repo.replace('/', '_')}_{sha}.json"
    if f.exists():
        return json.load(open(f, encoding="utf-8"))
    for tent in range(5):
        r = sess().get(f"https://api.github.com/repos/{repo}/commits/{sha}", timeout=60)
        if r.status_code in (403, 429):
            reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
            time.sleep(max(reset - time.time(), 5))
            continue
        if r.status_code in (404, 422):
            d = None
            break
        if r.ok:
            j = r.json()
            d = {"parents": [p["sha"] for p in j.get("parents", [])],
                 "files": [{k: x.get(k) for k in
                            ("filename", "status", "additions", "deletions", "patch")}
                           for x in j.get("files", [])]}
            break
        time.sleep(2 ** tent)
    else:
        return None
    json.dump(d, open(f, "w", encoding="utf-8"))
    return d


def raw(repo: str, ref: str, path: str) -> str | None:
    """Arquivo em um SHA fixo, com cache em disco (negativo inclusive)."""
    h = hashlib.sha1(f"{repo}@{ref}:{path}".encode()).hexdigest()
    f = CACHE_RAW / h[:2] / h
    if f.exists():
        b = f.read_bytes()
        return None if b == b"\x00404" else b.decode("utf-8", errors="replace")
    f.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
    for tent in range(5):
        try:
            r = requests.get(url, timeout=60)
        except requests.RequestException:
            time.sleep(2 ** tent)
            continue
        if r.status_code == 404:
            f.write_bytes(b"\x00404")
            return None
        if r.ok:
            f.write_bytes(r.content)
            return r.content.decode("utf-8", errors="replace")
        time.sleep(2 ** tent)
    return None


def linhas_do_patch(patch: str | None) -> tuple:
    """Mesmo filtro de ground_truth.commit_diff_lines."""
    add, rem = [], []
    for line in (patch or "").split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            code = line[1:].strip()
            if code and not code.startswith("//") and not code.startswith("#") and len(code) > 3:
                add.append(code)
        elif line.startswith("-") and not line.startswith("---"):
            code = line[1:].strip()
            if code and not code.startswith("//") and not code.startswith("#") and len(code) > 3:
                rem.append(code)
    return add, rem


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip()


def line_present(line: str, linhas_fork: list, set_fork: set, th: float = 0.85) -> bool:
    """ground_truth.line_present com o mesmo resultado; quick_ratio só poda."""
    n = _norm(line)
    if n in set_fork:
        return True
    sm = SequenceMatcher(None, n, "")
    sm.set_seq1(n)
    for cl in linhas_fork:
        if len(cl) < 3:
            continue
        sm.set_seq2(cl)
        if sm.real_quick_ratio() >= th and sm.quick_ratio() >= th and sm.ratio() >= th:
            return True
    return False


def oraculo_linhas(add, rem, fork_src) -> str:
    """ground_truth.verify_fork_gt, mesma regra (remoção se rem > 2×add; 15 sondas)."""
    remocao = len(rem) > len(add) * 2
    probe = (rem if remocao else add)[:15]
    if not probe:
        return "AMBIGUOUS"
    linhas = [_norm(l) for l in fork_src.split("\n")]
    s = set(linhas)
    pres = sum(line_present(l, linhas, s) for l in probe)
    conf = ((len(probe) - pres) if remocao else pres) / len(probe)
    if conf >= 0.70:
        return "CONFIRMED_PATCHED"
    if conf <= 0.30:
        return "CONFIRMED_VULNERABLE"
    return "AMBIGUOUS"


def verificar_commit(tarefa: dict) -> list:
    """Um commit de correção contra todos os ramos do produto. Roda em processo filho."""
    prod = PRODUTOS[POR_NOME[tarefa["produto"]]]
    sha = tarefa["fix_sha"]
    info = commit_api(prod["repo_fix"], sha)
    base = {"produto": tarefa["produto"], "cve": tarefa["cve"], "fix_sha": sha}
    if not info or not info["parents"]:
        return [{**base, "ramo": r, "filepath": None, "status": "SEM_COMMIT",
                 "status_ab": "SEM_COMMIT", "gt_linhas": "INACESSIVEL"}
                for r in tarefa["ramos"]]
    parent = info["parents"][0]
    arquivos = pd.select_patch_files(info["files"], "c")
    if not arquivos:
        return [{**base, "ramo": r, "filepath": None, "status": "SEM_ARQUIVO_C",
                 "status_ab": "SEM_ARQUIVO_C", "gt_linhas": "INACESSIVEL"}
                for r in tarefa["ramos"]]
    linhas = []
    for pf in arquivos:
        fp = pf["filename"]
        churn = (pf.get("additions") or 0) + (pf.get("deletions") or 0)
        post = raw(prod["repo_fix"], sha, fp)
        if post is None:
            continue
        pre = raw(prod["repo_fix"], parent, fp)
        ast_post = parse_code(post, "c")
        ast_pre = parse_code(pre, "c") if pre else None
        add, rem = linhas_do_patch(pf.get("patch"))
        for ramo, ponta in tarefa["ramos"].items():
            row = {**base, "ramo": ramo, "filepath": fp, "churn": churn,
                   "papel": "teste" if pd.is_test_file(fp) else "producao",
                   "sha_match": False, "sim_2a": None, "label_2a": None,
                   "sim_patch": None, "sim_vuln": None, "delta": None,
                   "label_2b": None, "method": None}
            fork = raw(prod["repo_ramo"], ponta, fp)
            if fork is None:
                row.update(status="FILE_NOT_FOUND", status_ab="FILE_NOT_FOUND",
                           gt_linhas="INACESSIVEL")
                linhas.append(row)
                continue
            row["gt_linhas"] = oraculo_linhas(add, rem, fork)
            if pd.layer1_sha(post, fork):
                row.update(sha_match=True, sim_2a=1.0, label_2a="CORRIGIDO",
                           status="CORRIGIDO", status_ab="CORRIGIDO")
                linhas.append(row)
                continue
            ast_fk = parse_code(fork, "c")
            _, _, sim_2a, method = compute_sim(ast_post, ast_fk)
            label_2a = classify(sim_2a)
            if ast_pre is not None:
                sim_vuln = compute_sim(ast_pre, ast_fk)[2]
                label_2b, delta = classify_dual(sim_2a, sim_vuln)
            else:
                sim_vuln, delta, label_2b = None, None, "NO_PRE_PATCH"
            row.update(sim_2a=round(sim_2a, 4), label_2a=label_2a,
                       sim_patch=round(sim_2a, 4),
                       sim_vuln=None if sim_vuln is None else round(sim_vuln, 4),
                       delta=None if delta is None else round(delta, 4),
                       label_2b=label_2b, method=method,
                       status=pd.decidir_status(label_2a, label_2b, sim_2a, delta, False),
                       status_ab=pd.decidir_status(label_2a, label_2b, sim_2a, delta, True))
            linhas.append(row)
    return linhas


def refazer_erros(alvo: Path, tarefas: dict):
    """
    Reprocessa os commits com status ERRO (na prática: RecursionError em _norm,
    AST profunda demais — tabelas geradas em C). Mesmo cálculo, só com pilha e
    limite de recursão maiores, numa thread sequencial.
    """
    import threading
    linhas = [json.loads(l) for l in open(alvo, encoding="utf-8")]
    shas = {r["fix_sha"] for r in linhas if r["status"] == "ERRO"}
    print(f"refazendo {len(shas)} commits com ERRO")
    novas = []

    def corpo():
        sys.setrecursionlimit(200000)
        for s in sorted(shas):
            try:
                novas.extend(verificar_commit(tarefas[s]))
            except Exception as e:  # noqa: BLE001
                print(f"  {s[:10]} continua falhando: {str(e)[:120]}")
                novas.extend(r for r in linhas if r["fix_sha"] == s)

    threading.stack_size(255 * 1024 * 1024)  # Windows exige < 256 MB
    t = threading.Thread(target=corpo)
    t.start()
    t.join()
    with open(alvo, "w", encoding="utf-8") as out:
        for r in linhas:
            if r["fix_sha"] not in shas:
                out.write(json.dumps(r, ensure_ascii=False) + "\n")
        for r in novas:
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  {sum(r['status'] == 'ERRO' for r in novas)} linhas ainda com ERRO")


def fase_verificar(args):
    oraculo = json.load(open(OUT / "oraculo_proveniencia.json", encoding="utf-8"))
    tarefas = {}
    for o in oraculo:
        if args.produto and o["produto"] != args.produto:
            continue
        t = tarefas.setdefault(o["fix_sha"], {"produto": o["produto"], "cve": o["cve"],
                                              "fix_sha": o["fix_sha"], "ramos": {}})
        t["ramos"][o["ramo"]] = o["ponta"]
    lista = sorted(tarefas.values(), key=lambda t: (t["produto"], t["cve"], t["fix_sha"]))
    if args.amostra:
        lista = lista[:args.amostra]
    alvo = OUT / "linhas_cruas.jsonl"
    if args.refazer_erros:
        return refazer_erros(alvo, tarefas)
    feitos = set()
    if alvo.exists() and not args.fresh:
        for l in open(alvo, encoding="utf-8"):
            feitos.add(json.loads(l)["fix_sha"])
    elif alvo.exists():
        alvo.unlink()
    lista = [t for t in lista if t["fix_sha"] not in feitos]
    print(f"{len(lista)} commits a verificar ({len(feitos)} já no arquivo)")
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=args.workers) as ex, \
         open(alvo, "a", encoding="utf-8") as out:
        futs = {ex.submit(verificar_commit, t): t for t in lista}
        for i, fu in enumerate(as_completed(futs), 1):
            t = futs[fu]
            try:
                rows = fu.result()
            except Exception as e:  # noqa: BLE001
                rows = [{"produto": t["produto"], "cve": t["cve"], "fix_sha": t["fix_sha"],
                         "ramo": r, "filepath": None, "status": "ERRO",
                         "status_ab": "ERRO", "gt_linhas": "INACESSIVEL",
                         "erro": str(e)[:200]} for r in t["ramos"]]
            for r in rows:
                out.write(json.dumps(r, ensure_ascii=False) + "\n")
            out.flush()
            if i % 25 == 0 or i == len(lista):
                el = time.time() - t0
                print(f"  {i}/{len(lista)}  {el/60:.1f} min  "
                      f"(~{el/i*(len(lista)-i)/60:.0f} min restantes)", flush=True)


# ─── fase 3: métricas ────────────────────────────────────────────────────────
def matriz(pares, pred_key, gt_fn):
    tp = fp = fn = tn = 0
    for p in pares:
        g = gt_fn(p)
        if g is None:
            continue
        pr = p[pred_key] == "CORRIGIDO"
        if g and pr: tp += 1
        elif not g and pr: fp += 1
        elif g: fn += 1
        else: tn += 1
    n = tp + fp + fn + tn
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    po = (tp + tn) / n if n else 0.0
    pe = (((tp + fp) * (tp + fn)) + ((fn + tn) * (fp + tn))) / n / n if n else 0.0
    k = (po - pe) / (1 - pe) if pe != 1 else 0.0
    return {"n": n, "TP": tp, "FP": fp, "FN": fn, "TN": tn, "P": round(P, 3),
            "R": round(R, 3), "F1": round(F, 3), "acc": round(po, 3), "kappa": round(k, 3)}


def fase_metricas(args):
    oraculo = json.load(open(OUT / "oraculo_proveniencia.json", encoding="utf-8"))
    cruas = [json.loads(l) for l in open(OUT / "linhas_cruas.jsonl", encoding="utf-8")]
    if any("fix_no_master" not in o for o in oraculo):
        cache = {}
        for o in oraculo:
            if o["fix_sha"] not in cache:
                pr = PRODUTOS[POR_NOME[o["produto"]]]
                cache[o["fix_sha"]] = is_ancestor(pr, o["fix_sha"], pr["master"])
            o["fix_no_master"] = cache[o["fix_sha"]]
        json.dump(oraculo, open(OUT / "oraculo_proveniencia.json", "w", encoding="utf-8"),
                  indent=1, ensure_ascii=False)
    prov = {(o["produto"], o["ramo"], o["fix_sha"]): o for o in oraculo}

    # agrega por (produto, ramo, CVE): união entre commits e entre produção/teste
    grupos = defaultdict(list)
    for r in cruas:
        grupos[(r["produto"], r["ramo"], r["cve"])].append(r)
    pares = []
    _GT_P = {"CONFIRMED_PATCHED": 3, "CONFIRMED_VULNERABLE": 2, "AMBIGUOUS": 1, "INACESSIVEL": 0}
    _PROV_P = {"HERANCA": 4, "MERGE": 4, "BACKPORT": 4, "SEM_CORRECAO": 1, "INACESSIVEL": 0}
    for (produto, ramo, cve), rows in grupos.items():
        st = [r["status"] for r in rows]
        ab = [r["status_ab"] for r in rows]
        shas = sorted({r["fix_sha"] for r in rows})
        provs = [prov[(produto, ramo, s)] for s in shas if (produto, ramo, s) in prov]
        melhor = max(provs, key=lambda o: _PROV_P[o["proveniencia"]])
        pares.append({
            "produto": produto, "ramo": ramo, "cve": cve, "fix_shas": shas,
            "vic": melhor["vic"], "fix_data": melhor["fix_data"],
            "status": pd._best_status(st) if st else "ERRO",
            "status_ab": pd._best_status(ab) if ab else "ERRO",
            "proveniencia": melhor["proveniencia"],
            "fix_no_master": any(o["fix_no_master"] for o in provs),
            "gt_linhas": max((r["gt_linhas"] for r in rows), key=lambda g: _GT_P.get(g, 0)),
        })
    json.dump(pares, open(OUT / "pares_agregados.json", "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)

    verificavel = lambda p: p["status"] in ("CORRIGIDO", "ZONA_INCERTEZA", "VULNERAVEL",
                                           "NAO_CORRIGIDO")
    gt_prov = lambda p: (None if p["proveniencia"] == "INACESSIVEL"
                         else p["proveniencia"] != "SEM_CORRECAO")
    # refinado: SEM_CORRECAO só conta como negativo se o fix está na linha principal
    gt_ref = lambda p: (None if p["proveniencia"] == "SEM_CORRECAO" and not p["fix_no_master"]
                        else gt_prov(p))
    gt_lin = lambda p: {"CONFIRMED_PATCHED": True, "CONFIRMED_VULNERABLE": False}.get(p["gt_linhas"])

    res = {"populacao": {}, "metricas": {}, "concordancia_oraculos": {}}
    for prodnome in ["linux", "ffmpeg", "php", None]:
        sub = [p for p in pares if prodnome is None or p["produto"] == prodnome]
        nome = prodnome or "TOTAL"
        if not sub:
            continue
        ver = [p for p in sub if verificavel(p)]
        res["populacao"][nome] = {
            "pares": len(sub), "verificaveis": len(ver),
            "status": dict(Counter(p["status"] for p in sub)),
            "status_ab": dict(Counter(p["status_ab"] for p in sub)),
            "proveniencia": dict(Counter(p["proveniencia"] for p in sub)),
            "proveniencia_verificaveis": dict(Counter(p["proveniencia"] for p in ver)),
        }
        triv = [{**p, "triv": "CORRIGIDO"} for p in ver]
        m = {}
        gt_cons = lambda p: (gt_ref(p) if gt_ref(p) is not None and gt_ref(p) == gt_lin(p)
                             else None)
        for onome, ofn in (("proveniencia", gt_prov), ("proveniencia_refinada", gt_ref),
                           ("linhas", gt_lin), ("consenso", gt_cons)):
            m[onome] = {"uniao": matriz(ver, "status", ofn),
                        "regra_ab": matriz(ver, "status_ab", ofn),
                        "trivial": matriz(triv, "triv", ofn)}
        # só os pares em que houve propagação a decidir (ramo nascido antes do fix)
        prop = [p for p in ver if p["proveniencia"] != "HERANCA"]
        triv_p = [{**p, "triv": "CORRIGIDO"} for p in prop]
        for onome, ofn in (("proveniencia", gt_prov), ("proveniencia_refinada", gt_ref),
                           ("consenso", gt_cons)):
            m[f"{onome}_sem_heranca"] = {"uniao": matriz(prop, "status", ofn),
                                          "regra_ab": matriz(prop, "status_ab", ofn),
                                          "trivial": matriz(triv_p, "triv", ofn)}
        # o oráculo por linhas julgado pela proveniência refinada
        ol = [{**p, "pred_lin": "CORRIGIDO" if gt_lin(p) else "X"}
              for p in ver if gt_lin(p) is not None]
        m["oraculo_linhas_vs_proveniencia_refinada"] = {
            "todos": matriz(ol, "pred_lin", gt_ref),
            "sem_heranca": matriz([p for p in ol if p["proveniencia"] != "HERANCA"],
                                  "pred_lin", gt_ref)}
        res["metricas"][nome] = m
        both = [p for p in ver if gt_prov(p) is not None and gt_lin(p) is not None]
        res["concordancia_oraculos"][nome] = {
            "n": len(both),
            "concordam": sum(gt_prov(p) == gt_lin(p) for p in both),
        }
    # verificabilidade por idade do fix (mesma leitura do run final72 do Matrix)
    faixas = [("ate_2012", "2012"), ("2013_16", "2016"), ("2017_19", "2019"),
              ("2020_21", "2021"), ("2022_23", "2023"), ("2024_mais", "9999")]
    por_idade = {}
    for p in pares:
        if not verificavel(p):
            continue
        ano = (p["fix_data"] or "0000")[:4]
        nome = next(n for n, lim in faixas if ano <= lim)
        d = por_idade.setdefault(nome, {"n": 0, "resolvidos": 0, "heranca": 0})
        d["n"] += 1
        d["resolvidos"] += p["status"] != "ZONA_INCERTEZA"
        d["heranca"] += p["proveniencia"] == "HERANCA"
    res["verificabilidade_por_idade"] = {
        n: {**por_idade[n], "taxa_resolvidos": round(por_idade[n]["resolvidos"] / por_idade[n]["n"], 3)}
        for n, _ in faixas if n in por_idade}
    print("\nverificabilidade por idade do fix:")
    for n, d in res["verificabilidade_por_idade"].items():
        print(f"  {n:<10} n={d['n']:<5} resolvidos {d['taxa_resolvidos']:.1%}")
    json.dump(res, open(OUT / "metricas_patchlens.json", "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)
    for nome, m in res["metricas"].items():
        print(f"\n== {nome} == {res['populacao'][nome]['pares']} pares, "
              f"{res['populacao'][nome]['verificaveis']} verificáveis")
        for onome, regras in m.items():
            for regra, x in regras.items():
                print(f"  {onome:<26} {regra:<9} n={x['n']:<5} TP {x['TP']:<5} FP {x['FP']:<5} "
                      f"FN {x['FN']:<5} TN {x['TN']:<5} P {x['P']:.3f} R {x['R']:.3f} "
                      f"F1 {x['F1']:.3f} k {x['kappa']:.3f}")
    print(f"\n→ {OUT / 'metricas_patchlens.json'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fase", choices=["oraculo", "verificar", "metricas"])
    ap.add_argument("--produto", choices=["linux", "ffmpeg", "php"])
    ap.add_argument("--amostra", type=int)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--refazer-erros", action="store_true")
    args = ap.parse_args()
    {"oraculo": fase_oraculo, "verificar": fase_verificar, "metricas": fase_metricas}[args.fase](args)


if __name__ == "__main__":
    main()
