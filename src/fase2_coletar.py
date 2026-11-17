#!/usr/bin/env python3
"""
FASE 2 - Coleta no ecossistema Matrix ampliado.

Tres passos independentes, todos com checkpoint e retomada (interrompa e rode de
novo a vontade: o que ja foi coletado nao e refeito).

  passo 1  metadados       ~102 chamadas   preenche linguagem real, forks, push
  passo 2  advisories/CVE  ~102 chamadas   GHSA publicados no proprio repositorio
  passo 3  rede de forks   ~102 x amostra  divergencia (ahead_by) por fork

Ordem recomendada: rodar 1 e 2 para TODOS os elegiveis (barato, ~3 min) e so
depois decidir onde gastar o orcamento caro do passo 3.

Uso:
    export GITHUB_TOKEN=ghp_...
    python3 fase2_coletar.py manifesto_ecossistema_matrix.csv --passo 1
    python3 fase2_coletar.py manifesto_ecossistema_matrix.csv --passo 2
    python3 fase2_coletar.py manifesto_ecossistema_matrix.csv --passo 3 \
        --amostra-forks 30 --camada Bridge
    python3 fase2_coletar.py manifesto_ecossistema_matrix.csv --exportar fase2.csv

Cache em ./cache_fase2/*.json (um arquivo por repositorio, versionavel em git
para garantir reprodutibilidade da coleta).
"""
import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
CACHE = Path("dados/cache_fase2")
# JavaScript entra porque matrix-appservice-irc, ja processado no Exp 3, esta
# rotulado como JavaScript no diretorio oficial. Sem ele, a coleta pularia
# matrix-js-sdk, matrix-appservice-node, Cinny e o proprio appservice-irc, que
# fazem parte do recorte aprovado pelo orientador.
LINGUAGENS_PIPELINE = {"Go", "TypeScript", "JavaScript", "Python", "Rust",
                       "Kotlin", "Swift"}


# --------------------------------------------------------------------------- #
# camada de rede
# --------------------------------------------------------------------------- #
def api(path, tentativas=3):
    """GET na API do GitHub, respeitando rate limit. Devolve (dados, status)."""
    req = Request(API + path)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "fase2-matrix-forks")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    for t in range(tentativas):
        try:
            with urlopen(req, timeout=45) as r:
                dados = json.load(r)
                rest = r.headers.get("X-RateLimit-Remaining")
                if rest is not None and int(rest) < 10:
                    reset = int(r.headers.get("X-RateLimit-Reset", "0"))
                    espera = max(0, reset - int(time.time())) + 3
                    print(f"    [rate limit] pausando {espera}s", file=sys.stderr)
                    time.sleep(espera)
                return dados, 200
        except HTTPError as e:
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset")
                espera = (max(0, int(reset) - int(time.time())) + 3) if reset else 60
                print(f"    [{e.code}] pausando {espera}s", file=sys.stderr)
                time.sleep(min(espera, 3900))
                continue
            return None, e.code          # 404, 451 (DMCA), 409 (repo vazio)
        except (OSError, HTTPException, json.JSONDecodeError):
            # OSError cobre URLError, TimeoutError e ConnectionResetError;
            # HTTPException cobre RemoteDisconnected/BadStatusLine, que o GitHub
            # dispara ao derrubar conexao keep-alive no meio de uma coleta longa.
            time.sleep(5 * (t + 1))
    return None, 0


def slug(url):
    if url and "github.com" in url:
        p = url.split("github.com/", 1)[1].strip("/").rstrip("/").split("/")
        if len(p) >= 2:
            return f"{p[0]}/{p[1].removesuffix('.git')}"
    return ""


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #
def caminho_cache(s):
    CACHE.mkdir(exist_ok=True)
    return CACHE / (s.replace("/", "__") + ".json")


def carregar(s):
    p = caminho_cache(s)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"slug": s}


def salvar(s, d):
    d["coletado_em"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    caminho_cache(s).write_text(
        json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


# --------------------------------------------------------------------------- #
# passos
# --------------------------------------------------------------------------- #
def passo1(s, d, _args):
    """Metadados do repositorio. Corrige a linguagem declarada no diretorio."""
    if "meta" in d:
        return False
    r, status = api(f"/repos/{s}")
    if r is None:
        d["meta"] = {"erro": status}
        return True
    d["meta"] = {
        "linguagem": r.get("language"),
        "forks": r.get("forks_count"),
        "stars": r.get("stargazers_count"),
        "watchers": r.get("subscribers_count"),
        "tamanho_kb": r.get("size"),
        "arquivado": r.get("archived"),
        "desabilitado": r.get("disabled"),
        "branch_padrao": r.get("default_branch"),
        "criado_em": r.get("created_at"),
        "push_em": r.get("pushed_at"),
        "e_fork": r.get("fork"),
        "upstream": (r.get("parent") or {}).get("full_name"),
    }
    return True


def passo2(s, d, _args):
    """Advisories de seguranca publicados no proprio repositorio (GHSA/CVE)."""
    if "advisories" in d:
        return False
    r, status = api(f"/repos/{s}/security-advisories?per_page=100&state=published")
    if r is None:
        d["advisories"] = {"erro": status, "itens": []}
        return True
    itens = []
    for a in r if isinstance(r, list) else []:
        itens.append({
            "ghsa": a.get("ghsa_id"),
            "cve": a.get("cve_id"),
            "severidade": a.get("severity"),
            "cvss": ((a.get("cvss") or {}).get("score")),
            "cwes": [c.get("cwe_id") for c in (a.get("cwes") or [])],
            "publicado_em": a.get("published_at"),
            "resumo": (a.get("summary") or "")[:180],
        })
    d["advisories"] = {"erro": None, "itens": itens}
    return True


def passo3(s, d, args):
    """Rede de forks: quantos estao ativos e quantos divergiram (ahead_by > 0)."""
    # A chave de cache e a TRIPLA de parametros: mudar --paginas-forks ou
    # --dias-atividade tem de invalidar, senao o dataset sai com parametros
    # misturados e nada no CSV denuncia.
    fa_ant = d.get("forks_amostra") or {}
    if (fa_ant.get("amostra"), fa_ant.get("paginas_percorridas"),
            fa_ant.get("dias_atividade")) == (args.amostra_forks,
                                              args.paginas_forks,
                                              args.dias_atividade):
        return False
    meta = d.get("meta") or {}
    if meta.get("erro") or not meta.get("forks"):
        d["forks_amostra"] = {"amostra": args.amostra_forks, "ativos": 0,
                              "divergentes": 0, "detalhe": [], "nota": "sem forks"}
        return True
    base = meta.get("branch_padrao") or "main"
    limite = datetime.now(timezone.utc) - timedelta(days=args.dias_atividade)

    # sort=newest ordena por data de CRIACAO do fork, nao por atividade; a API
    # nao oferece ordenacao por pushed_at. Paginamos e ordenamos localmente.
    # Consequencia metodologica: para redes muito grandes (synapse,
    # matrix-js-sdk) esta e uma AMOSTRA das paginas percorridas, nao o censo da
    # rede. Declarar na dissertacao. Aumente --paginas-forks para reduzir o vies.
    forks, pagina, erro_paginacao, exauriu = [], 1, False, False
    while pagina <= args.paginas_forks:
        r, st = api(f"/repos/{s}/forks?sort=newest"
                    f"&per_page=100&page={pagina}")
        if not r:
            # lista vazia (fim) e falha de rede sao indistinguiveis por `not r`;
            # sem isto, rede_completa afirma "vi a rede inteira" quando na
            # verdade a paginacao foi truncada por erro.
            erro_paginacao = st != 200
            exauriu = not erro_paginacao
            break
        forks.extend(r)
        if len(r) < 100:
            exauriu = True      # pagina incompleta = fim real da lista
            break
        pagina += 1

    recentes = []
    for f in forks:
        p = f.get("pushed_at")
        if p and datetime.fromisoformat(p.replace("Z", "+00:00")) >= limite:
            recentes.append(f)
    recentes.sort(key=lambda f: f.get("pushed_at") or "", reverse=True)
    recentes = recentes[:args.amostra_forks]

    detalhe = []
    for f in recentes:
        dono = f["owner"]["login"]
        br = f.get("default_branch") or base
        cmp_, st = api(f"/repos/{s}/compare/{base}...{dono}:{br}")
        if cmp_ is None:
            detalhe.append({"fork": f["full_name"], "erro": st})
            continue
        detalhe.append({
            "fork": f["full_name"],
            "ahead_by": cmp_.get("ahead_by", 0),
            "behind_by": cmp_.get("behind_by", 0),
            "push_em": f.get("pushed_at"),
            "stars": f.get("stargazers_count", 0),
        })
    d["forks_amostra"] = {
        "amostra": args.amostra_forks,
        "dias_atividade": args.dias_atividade,
        "forks_vistos": len(forks),
        "paginas_percorridas": args.paginas_forks,
        # "Vi a rede inteira" = a paginacao chegou ao FIM da lista (pagina com
        # menos de 100 itens), nao "o total bate com forks_count": o contador do
        # GitHub inclui forks deletados/privados que a API nao lista, entao
        # comparar com ele produz falso incompleto (ex.: 359 vistos de 360).
        "rede_completa": exauriu and not erro_paginacao,
        "erro_paginacao": erro_paginacao,
        "forks_declarados": meta.get("forks"),   # gap = deletados/privados
        "ativos": len(recentes),
        "divergentes": sum(1 for x in detalhe if x.get("ahead_by", 0) > 0),
        "detalhe": detalhe,
    }
    return True


PASSOS = {1: passo1, 2: passo2, 3: passo3}


# --------------------------------------------------------------------------- #
# exportacao
# --------------------------------------------------------------------------- #
def exportar(linhas, saida):
    campos = ["id", "camada", "nome", "slug", "linguagem_diretorio",
              "linguagem_github", "maturidade", "arquivado", "forks", "stars",
              "push_em", "n_cves", "cves", "severidade_max",
              "forks_ativos", "forks_divergentes", "apto_fase2"]
    out = []
    for l in linhas:
        s = slug(l["url_repositorio"])
        if not s:
            continue
        d = carregar(s)
        meta = d.get("meta") or {}
        adv = (d.get("advisories") or {}).get("itens") or []
        fa = d.get("forks_amostra") or {}
        cves = [a["cve"] for a in adv if a.get("cve")]
        sev = [a.get("severidade") for a in adv if a.get("severidade")]
        ordem = ["low", "moderate", "high", "critical"]
        sev_max = max(sev, key=lambda x: ordem.index(x)
                      if x in ordem else -1, default="")
        apto = (bool(cves) and (fa.get("divergentes") or 0) > 0
                and (meta.get("linguagem") in LINGUAGENS_PIPELINE))
        out.append({
            "id": l["id"], "camada": l["camada"], "nome": l["nome"], "slug": s,
            "linguagem_diretorio": l["linguagem"],
            "linguagem_github": meta.get("linguagem", ""),
            "maturidade": l["maturidade"],
            "arquivado": meta.get("arquivado", ""),
            "forks": meta.get("forks", ""), "stars": meta.get("stars", ""),
            "push_em": meta.get("push_em", ""),
            "n_cves": len(cves), "cves": ";".join(cves),
            "severidade_max": sev_max,
            "forks_ativos": fa.get("ativos", ""),
            "forks_divergentes": fa.get("divergentes", ""),
            "apto_fase2": "sim" if apto else "nao",
        })
    with open(saida, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        w.writerows(out)
    aptos = sum(1 for o in out if o["apto_fase2"] == "sim")
    com_cve = sum(1 for o in out if o["n_cves"])
    print(f"{len(out)} linhas -> {saida}")
    print(f"  com >=1 CVE publicada : {com_cve}")
    print(f"  aptos a Fase 2        : {aptos}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifesto")
    ap.add_argument("--passo", type=int, choices=[1, 2, 3])
    ap.add_argument("--exportar", metavar="SAIDA.csv")
    ap.add_argument("--camada", help="restringe a uma camada (ex.: Bridge)")
    ap.add_argument("--amostra-forks", type=int, default=30)
    ap.add_argument("--dias-atividade", type=int, default=365)
    ap.add_argument("--paginas-forks", type=int, default=5,
                    help="paginas de 100 forks percorridas por repositorio; "
                         "5 = ate 500 forks vistos antes da amostragem")
    ap.add_argument("--todas-linguagens", action="store_true",
                    help="nao filtra pelas 6 linguagens do pipeline")
    args = ap.parse_args()

    linhas = list(csv.DictReader(open(args.manifesto, encoding="utf-8")))
    elegiveis, vistos = [], set()
    for l in linhas:
        s = slug(l.get("url_repositorio", ""))
        if not s or s in vistos:
            continue
        if not args.todas_linguagens and l["linguagem"] not in LINGUAGENS_PIPELINE:
            continue
        if args.camada and l["camada"] != args.camada:
            continue
        vistos.add(s)
        elegiveis.append(l)

    if args.exportar:
        exportar(elegiveis, args.exportar)
        return
    if not args.passo:
        ap.error("informe --passo 1|2|3 ou --exportar")
    if not TOKEN:
        print("ERRO: defina GITHUB_TOKEN (sem token o limite e 60 req/h, "
              "insuficiente para 102 repositorios).", file=sys.stderr)
        sys.exit(1)

    fn = PASSOS[args.passo]
    novos = 0
    for i, l in enumerate(elegiveis, 1):
        s = slug(l["url_repositorio"])
        d = carregar(s)
        print(f"[{i}/{len(elegiveis)}] passo {args.passo}: {s}", file=sys.stderr)
        if fn(s, d, args):
            salvar(s, d)
            novos += 1
        else:
            print("    (em cache, pulando)", file=sys.stderr)
    print(f"\nPasso {args.passo}: {novos} repositorios coletados, "
          f"{len(elegiveis) - novos} ja em cache.", file=sys.stderr)


if __name__ == "__main__":
    main()
