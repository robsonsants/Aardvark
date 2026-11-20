#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monta o dataset temporal do ecossistema: as datas que a verificação não grava.

DATAS MINERADAS PELA API DO GITHUB
  1. data do commit de correção no upstream          (1 chamada por fix_sha)
  2. created_at e pushed_at de cada fork             (1 chamada por fork)
  3. ahead_by / behind_by de cada fork contra o upstream

A data de criação do fork, comparada com as datas dos commits de correção, separa os
pares de herança dos de propagação. Os commits atrás do upstream entram nos fatores
associados (QP2.3). O tempo até a correção é medido pelo grafo do Git, em
tempo_correcao.py.

Uso:
    python src/dataset_temporal.py --run resultados/matrix/top10
    python src/dataset_temporal.py --run resultados/matrix/top10 --token ghp_xxx
"""
import argparse
import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import requests
except ImportError:
    print("Falta a lib 'requests' (pip install requests).")
    sys.exit(1)

API = "https://api.github.com"


def ler_token(proj: Path) -> str:
    p = proj / ".env"
    if p.exists():
        for linha in io.open(p, encoding="utf-8", errors="ignore"):
            if linha.strip().startswith("GITHUB_TOKEN="):
                return linha.split("=", 1)[1].strip()
    return os.getenv("GITHUB_TOKEN", "")


class GH:
    def __init__(self, token: str):
        self.s = requests.Session()
        self.s.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "dataset-temporal/1.0",
            **({"Authorization": f"token {token}"} if token else {}),
        })
        self.n = 0

    def get(self, caminho: str, **params):
        for tentativa in range(3):
            r = self.s.get(f"{API}/{caminho}", params=params, timeout=30)
            self.n += 1
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429):          # rate limit
                espera = 5 * (tentativa + 1)
                print(f"    [rate limit] aguardando {espera}s...")
                time.sleep(espera)
                continue
            return None
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--token", default=None)
    args = ap.parse_args()

    base = Path(args.run)
    proj = Path(os.path.dirname(os.path.abspath(__file__)))
    gh = GH(args.token or ler_token(proj))

    linhas = json.load(open(base / "dissertation_resultados.json", encoding="utf-8"))
    vered = json.load(open(base / "dissertation_veredictos.json", encoding="utf-8"))
    cob = json.load(open(base / "dissertation_cobertura.json", encoding="utf-8"))
    cob_por_fork = {c["fork"]: c for c in (cob if isinstance(cob, list) else cob.values())}

    # ── 1. data do commit de correcao ───────────────────────────────────────
    fix_shas = sorted({(r["upstream"], r["fix_sha"]) for r in linhas})
    print(f"[1/3] Data dos {len(fix_shas)} commits de correção...")
    data_fix = {}
    for up, sha in fix_shas:
        c = gh.get(f"repos/{up}/commits/{sha}")
        d = (((c or {}).get("commit") or {}).get("committer") or {}).get("date")
        data_fix[(up, sha)] = d
        print(f"    {up.split('/')[-1]:<32} {sha[:8]}  {d or 'não obtida'}")

    # ── 2. metadados de cada fork ───────────────────────────────────────────
    forks = sorted({v["fork"] for v in vered})
    up_do_fork = {v["fork"]: v["upstream"] for v in vered}
    print(f"\n[2/3] Metadados de {len(forks)} forks...")
    meta = {}
    for f in forks:
        r = gh.get(f"repos/{f}") or {}
        up = up_do_fork[f]
        base_branch = (gh.get(f"repos/{up}") or {}).get("default_branch", "main")
        fb = r.get("default_branch") or "main"
        cmp = gh.get(f"repos/{up}/compare/{base_branch}...{f.split('/')[0]}:{fb}") or {}
        meta[f] = {
            "created_at": r.get("created_at"),
            "pushed_at": r.get("pushed_at"),
            "ahead_by": cmp.get("ahead_by"),
            "behind_by": cmp.get("behind_by"),
            "stars": r.get("stargazers_count"),
            "default_branch": fb,
        }
        print(f"    {f:<44} criado {str(meta[f]['created_at'])[:10]}  "
              f"ahead={meta[f]['ahead_by']} behind={meta[f]['behind_by']}")

    # ── 3. montagem ─────────────────────────────────────────────────────────
    print("\n[3/3] Montando o dataset...")
    pares = []
    for r in linhas:
        chave = (r["upstream"], r["fix_sha"])
        d_fix = data_fix.get(chave)
        m = meta.get(r["fork"], {})
        pares.append({
            "upstream": r["upstream"], "categoria": r["category"],
            "linguagem": r["language"], "cve_id": r["cve_id"],
            "fork": r["fork"], "status": r["status"],
            "arquivo": r["filepath"],
            "eh_arquivo_de_teste": "sim" if ("test" in r["filepath"].lower()) else "nao",
            "fix_sha": r["fix_sha"], "data_fix_upstream": d_fix,
            "sim_2a": r.get("sim_2a"), "delta": r.get("delta"),
            "metrica": r.get("method"),
            "fork_created_at": m.get("created_at"),
            "fork_pushed_at": m.get("pushed_at"),
            "ahead_by": m.get("ahead_by"), "behind_by": m.get("behind_by"),
            "stars": m.get("stars"),
        })

    tabela_forks = []
    for f in forks:
        m = meta[f]
        c = cob_por_fork.get(f, {})
        tabela_forks.append({
            "fork": f, "upstream": up_do_fork[f],
            "categoria": next(v["category"] for v in vered if v["fork"] == f),
            "linguagem": next(v["language"] for v in vered if v["fork"] == f),
            "created_at": m["created_at"], "pushed_at": m["pushed_at"],
            "ahead_by": m["ahead_by"], "behind_by": m["behind_by"],
            "stars": m["stars"],
            "n_cves": c.get("n_cves_total"), "n_corrigidas": c.get("n_corrigidas"),
            "cobertura_pct": c.get("cobertura_pct"),
        })

    def grava_csv(nome, linhas_dic):
        if not linhas_dic:
            return
        with open(base / nome, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(linhas_dic[0].keys()), delimiter=";")
            w.writeheader()
            w.writerows(linhas_dic)
        print(f"    -> {base / nome}  ({len(linhas_dic)} linhas)")

    grava_csv("dataset_temporal_pares.csv", pares)
    grava_csv("dataset_temporal_forks.csv", tabela_forks)

    resumo = {
        "run": str(base),
        "gerado_em": datetime.now(timezone.utc).isoformat(),
        "chamadas_api": gh.n,
        "n_pares": len(pares), "n_forks": len(tabela_forks),
        "pares": pares, "forks": tabela_forks,
    }
    json.dump(resumo, open(base / "dataset_temporal.json", "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)
    print(f"    -> {base / 'dataset_temporal.json'}")
    print(f"\nChamadas à API: {gh.n}")


if __name__ == "__main__":
    main()
