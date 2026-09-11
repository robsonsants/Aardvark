#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fase1_fix_commits.py - Phase 1 (light): CVE -> fix commit, without depending on NVD
==================================================================================
Discovers the fix commits of the CVEs of every repository marked as eligible for the
wider Phase 2, using the GitHub Global Advisory Database as the primary source.

  Primary source : GET /advisories/{GHSA} - the `references` field usually carries the
                   URL of the fix commit.
  Fallback       : NVD (GET /cves/2.0?cveId=...), used only for CVEs whose GHSA has no
                   commit reference. The NVD key is optional (without it the rate drops
                   to ~1 request / 6 s, which is enough for a few dozen CVEs).

Every SHA is validated against the target repository before being written out, which
also recovers repositories that were renamed (e.g. poljar/matrix-nio).

Input : fase2.csv (rows with apto_fase2 == "sim") + cache_fase2/*.json (CVE -> GHSA map)
Output: CSV in the exact format expected by pipeline_dissertation.py
        id;github_owner;github_repo;dependency;commit_sha;commit_url;no_files;additions;deletions;changes

Usage:
    python fase1_fix_commits.py --entrada fase2.csv \
        --saida resultados_YYYY-MM-DD/cves-fixing-commits-dataset.csv \
        --token YOUR_TOKEN
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests

GH_API  = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE   = Path("cache_fase2")

COMMIT_RE = re.compile(
    r"https?://github\.com/([\w.\-]+)/([\w.\-]+)/(?:commit|commits)/([0-9a-f]{7,40})",
    re.I,
)
PR_COMMIT_RE = re.compile(
    r"https?://github\.com/([\w.\-]+)/([\w.\-]+)/pull/\d+/commits/([0-9a-f]{7,40})",
    re.I,
)


class GH:
    def __init__(self, token):
        self.s = requests.Session()
        h = {"Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            h["Authorization"] = "Bearer " + token
        self.s.headers.update(h)

    def get(self, path, tries=3):
        url = path if path.startswith("http") else GH_API + "/" + path
        for i in range(tries):
            try:
                r = self.s.get(url, timeout=30)
            except requests.RequestException as e:
                print("    ! rede: %s" % e)
                time.sleep(3 * (i + 1))
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429):
                reset = r.headers.get("X-RateLimit-Reset")
                wait = 60
                if reset:
                    try:
                        wait = max(5, int(reset) - int(time.time()) + 5)
                    except ValueError:
                        pass
                print("    ! rate limit; aguardando %ss" % min(wait, 300))
                time.sleep(min(wait, 300))
                continue
            if r.status_code == 404:
                return None
            print("    ! HTTP %s em %s" % (r.status_code, url))
            time.sleep(2 * (i + 1))
        return None


def cve_para_ghsa(slug):
    """Le cache_fase2/<owner>__<repo>.json e devolve {CVE: GHSA}."""
    owner, repo = slug.split("/")
    p = CACHE / ("%s__%s.json" % (owner, repo))
    if not p.exists():
        return {}
    d = json.loads(p.read_text(encoding="utf-8"))
    itens = (d.get("advisories") or {}).get("itens") or []
    return {i["cve"]: i["ghsa"] for i in itens if i.get("cve") and i.get("ghsa")}


def refs_do_ghsa(gh, ghsa):
    d = gh.get("advisories/" + ghsa)
    if not d:
        return []
    refs = list(d.get("references") or [])
    for campo in ("description", "summary"):
        if d.get(campo):
            refs.append(d[campo])
    return refs


def refs_do_nvd(cve, nvd_key):
    h = {"apiKey": nvd_key} if nvd_key else {}
    for i in range(3):
        try:
            r = requests.get(NVD_API, params={"cveId": cve}, headers=h, timeout=45)
        except requests.RequestException as e:
            print("    ! NVD rede: %s" % e)
            time.sleep(6 * (i + 1))
            continue
        if r.status_code == 200:
            try:
                vulns = r.json().get("vulnerabilities") or []
            except ValueError:
                return []
            if not vulns:
                return []
            return [x.get("url", "") for x in vulns[0]["cve"].get("references", [])]
        if r.status_code in (403, 503, 429):
            time.sleep(6 * (i + 1))
            continue
        return []
    return []


def shas_das_refs(refs, owner, repo):
    """
    SHAs de commit citados nas referencias, na ordem em que aparecem.

    Nao filtra por owner/repo da URL: repositorios renomeados/transferidos
    (ex.: poljar/matrix-nio -> matrix-nio/matrix-nio) publicam a referencia com
    o dono antigo. Como o SHA e um hash de conteudo, a validacao correta e
    perguntar ao repositorio-alvo se aquele commit existe nele — feito depois em
    stats_do_commit(), que descarta (404) o que nao pertence ao alvo.
    """
    out, vistos = [], set()
    for ref in refs:
        if not ref:
            continue
        for rx in (COMMIT_RE, PR_COMMIT_RE):
            for o, r, sha in rx.findall(ref):
                k = sha.lower()
                if k not in vistos:
                    vistos.add(k)
                    out.append(sha)
    return out


def stats_do_commit(gh, owner, repo, sha):
    d = gh.get("repos/%s/%s/commits/%s" % (owner, repo, sha))
    if not d:
        return None
    st = d.get("stats") or {}
    return {
        "commit_sha": d.get("sha", sha),
        "commit_url": d.get("html_url",
                            "https://github.com/%s/%s/commit/%s" % (owner, repo, sha)),
        "no_files": len(d.get("files") or []),
        "additions": st.get("additions", 0),
        "deletions": st.get("deletions", 0),
        "changes": st.get("total", 0),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entrada", default="fase2.csv")
    ap.add_argument("--saida", required=True)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    ap.add_argument("--nvd-key", default=os.environ.get("NVD_TOKEN", ""))
    ap.add_argument("--sem-nvd", action="store_true",
                    help="nao usar o fallback do NVD (so GHSA)")
    ap.add_argument("--slugs", default=None,
                    help="arquivo txt com um slug owner/repo por linha; restringe "
                         "a coleta a esses repositorios (ignora o filtro apto_fase2)")
    args = ap.parse_args()

    gh = GH(args.token)

    alvos = None
    if args.slugs:
        alvos = {l.strip() for l in open(args.slugs, encoding="utf-8")
                 if l.strip() and not l.startswith("#")}

    with open(args.entrada, newline="", encoding="utf-8") as f:
        linhas_entrada = list(csv.DictReader(f))

    if alvos is not None:
        # Selecao explicita (uma lista de repositorios fixada a mao): entra todo
        # repositorio da lista, mesmo sem CVE — "0 CVEs conhecidas" e resultado.
        aptos = [r for r in linhas_entrada if r["slug"] in alvos]
        faltando = alvos - {r["slug"] for r in aptos}
        for s_ in sorted(faltando):
            print("AVISO: %s nao esta em %s" % (s_, args.entrada))
    else:
        aptos = [r for r in linhas_entrada if r.get("apto_fase2") == "sim"]

    print("Repositorios aptos: %d" % len(aptos))
    linhas, sem_commit = [], []

    for n, row in enumerate(aptos, 1):
        slug = row["slug"]
        owner, repo = slug.split("/")
        cves = [c for c in (row.get("cves") or "").split(";") if c]
        mapa = cve_para_ghsa(slug)
        print("\n[%d/%d] %s - %d CVEs" % (n, len(aptos), slug, len(cves)))

        for cve in cves:
            ghsa = mapa.get(cve, "")
            refs = refs_do_ghsa(gh, ghsa) if ghsa else []
            shas = shas_das_refs(refs, owner, repo)
            origem = "ghsa"

            if not shas and not args.sem_nvd:
                refs_nvd = refs_do_nvd(cve, args.nvd_key)
                shas = shas_das_refs(refs_nvd, owner, repo)
                origem = "nvd"
                time.sleep(0.6 if args.nvd_key else 6.5)

            if not shas:
                print("  %s: sem commit nas referencias" % cve)
                sem_commit.append({"cve": cve, "slug": slug, "ghsa": ghsa})
                continue

            ok = 0
            for sha in shas:
                st = stats_do_commit(gh, owner, repo, sha)
                if not st:
                    continue
                linha = {"id": cve, "github_owner": owner,
                         "github_repo": repo, "dependency": "1"}
                linha.update(st)
                linhas.append(linha)
                ok += 1
            if ok == 0:
                # SHAs citados existiam na referencia mas nenhum pertence ao
                # repositorio-alvo (404 na validacao) — conta como sem commit.
                print("  %s: referencias citam commit(s) de outro repositorio" % cve)
                sem_commit.append({"cve": cve, "slug": slug, "ghsa": ghsa,
                                   "motivo": "commit fora do repositorio-alvo"})
            else:
                print("  %s: %d fix commit(s) [%s]" % (cve, ok, origem))

    saida = Path(args.saida)
    saida.parent.mkdir(parents=True, exist_ok=True)
    campos = ["id", "github_owner", "github_repo", "dependency", "commit_sha",
              "commit_url", "no_files", "additions", "deletions", "changes"]
    with open(saida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, delimiter=";")
        w.writeheader()
        w.writerows(linhas)

    faltas = saida.parent / "cves_sem_fix_commit.json"
    faltas.write_text(json.dumps(sem_commit, indent=2, ensure_ascii=False),
                      encoding="utf-8")

    cves_ok = len({l["id"] for l in linhas})
    print("\n" + "=" * 60)
    print("Fix commits gravados : %d (em %d CVEs)" % (len(linhas), cves_ok))
    print("CVEs sem commit      : %d  -> %s" % (len(sem_commit), faltas))
    print("Saida                : %s" % saida)


if __name__ == "__main__":
    main()
