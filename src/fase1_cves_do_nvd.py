#!/usr/bin/env python3
"""Mine fixing commits for CVEs discovered by the CPE/NVD census sweep.

fase1_fix_commits.py enumerates a repository's CVEs from the GHSA advisory
cache, so it cannot see CVEs that exist only in the NVD -- exactly the ones
censo_cpe_nvd.py recovers (synapse +33, olm +5, dendrite +2, ...). This script
takes those (slug, cve) pairs and reuses fase1's own helpers, so the output is
byte-compatible with cves-fixing-commits-dataset.csv.
"""
import argparse, csv, io, json, os, sys, time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fase1_fix_commits as f1

CAMPOS = ["id", "github_owner", "github_repo", "dependency", "commit_sha",
          "commit_url", "no_files", "additions", "deletions", "changes"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entrada", default="dados/censo_cpe_nvd.csv")
    ap.add_argument("--saida", required=True)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    ap.add_argument("--nvd-key", default=os.environ.get("NVD_TOKEN", ""))
    ap.add_argument("--excluir-ja-no-dataset", default="dados/cves-fixing-commits-dataset.csv")
    a = ap.parse_args()

    if not a.token:
        for l in open(".env", encoding="utf-8"):
            if l.startswith("GITHUB_TOKEN="):
                a.token = l.split("=", 1)[1].strip().strip('"')

    ja = set()
    if a.excluir_ja_no_dataset and os.path.exists(a.excluir_ja_no_dataset):
        for r in csv.DictReader(open(a.excluir_ja_no_dataset, encoding="utf-8-sig"),
                                delimiter=";"):
            ja.add((r["github_owner"] + "/" + r["github_repo"], r["id"]))

    pares = []
    for r in csv.DictReader(open(a.entrada, encoding="utf-8-sig"), delimiter=";"):
        if r["aceito"] != "sim":
            continue
        if (r["slug"], r["cve"]) in ja:
            continue
        pares.append((r["slug"], r["cve"]))
    print("%d pares (slug, cve) a minerar" % len(pares))

    gh = f1.GH(a.token)
    linhas, sem = [], []
    por_slug = {}
    for slug, cve in pares:
        por_slug.setdefault(slug, []).append(cve)

    for slug, cves in sorted(por_slug.items()):
        owner, repo = slug.split("/")
        print("\n%s - %d CVEs" % (slug, len(cves)))
        for cve in sorted(cves):
            refs = f1.refs_do_nvd(cve, a.nvd_key)
            time.sleep(0.6 if a.nvd_key else 6.5)
            shas = f1.shas_das_refs(refs, owner, repo)
            if not shas:
                print("  %s: sem commit nas referencias" % cve)
                sem.append({"cve": cve, "slug": slug})
                continue
            ok = 0
            for sha in shas:
                st = f1.stats_do_commit(gh, owner, repo, sha)
                if not st:
                    continue
                linha = {"id": cve, "github_owner": owner, "github_repo": repo,
                         "dependency": "1"}
                linha.update(st)
                linhas.append(linha)
                ok += 1
            if ok:
                print("  %s: %d fix commit(s) [nvd]" % (cve, ok))
            else:
                print("  %s: commits citados nao pertencem ao repo-alvo" % cve)
                sem.append({"cve": cve, "slug": slug,
                            "motivo": "commit fora do repositorio-alvo"})

    with io.open(a.saida, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS, delimiter=";")
        w.writeheader()
        w.writerows(linhas)
    json.dump(sem, open(os.path.splitext(a.saida)[0] + "_sem_commit.json", "w",
                        encoding="utf-8"), indent=2, ensure_ascii=False)
    print("\n" + "=" * 60)
    print("Fix commits gravados : %d (em %d CVEs)" % (linhas.__len__(),
                                                      len({l['id'] for l in linhas})))
    print("CVEs sem commit      : %d" % len(sem))
    print("Saida                : %s" % a.saida)


if __name__ == "__main__":
    main()
