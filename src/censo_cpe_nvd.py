#!/usr/bin/env python3
"""Sweep the ecosystem census for CVEs via CPE queries to the NVD.

Why: the census in fase2_coletar.py counts *repository security advisories*
(GHSA published in the repo itself). Archived, renamed or externally-tracked
projects publish none, so they come out with n_cves=0 even when the NVD knows
about them. matrix-org/olm is the proof: 0 advisories in the repo, 5 CVEs in
the NVD -- the same 5 reported by Damasceno et al. (SBSeg 2026), whose workflow
queries the NVD by CPE. This script closes that blind spot.

Attribution guard: a product name alone is not evidence (querying "go" would
drag in every Golang CVE). A CVE is only ACCEPTED when either
  (a) one of its references points at github.com/<slug>, or
  (b) the matched CPE vendor is in VENDORS_OK.
Anything else is reported as "duvidoso" and never merged automatically.

No NVD API key: the public limit is 5 requests per rolling 30s, so calls are
spaced by PAUSA seconds. Results are cached per product in cache_cpe_nvd/ so an
interrupted sweep resumes instead of re-querying.
"""
import argparse, csv, io, json, os, re, sys, time
import requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = "dados/cache_cpe_nvd"
PAUSA = 6.5          # sem chave de API: 5 req / 30s
VENDORS_OK = {"matrix", "matrix.org", "matrixorg", "element", "element-hq",
              "element_hq", "elementhq", "famedly", "nheko-reborn", "nheko",
              "t2bot", "vector", "vectorim", "vector_im"}
# nomes curtos ou de linguagem/plataforma: casariam com CVEs de terceiros
GENERICOS = {"go", "c", "java", "python", "rust", "web", "app", "sdk", "bot",
             "chat", "im", "ios", "android", "desktop", "server", "client",
             "bridge", "core", "api", "cli", "gui", "lib", "doc", "test"}


def produto_de(slug, nome):
    """Candidate CPE product names for a repository."""
    repo = slug.split("/")[-1].lower()
    cands = {repo, repo.replace("-", "_"), repo.replace("_", "-")}
    if nome:
        n = nome.strip().lower().replace(" ", "-")
        cands |= {n, n.replace("-", "_")}
    # Limite em 2, nao 3: "olm" tem exatamente 3 letras e foi o caso que motivou
    # este script (0 advisories no repo, 5 CVEs no NVD). Quem protege contra nome
    # generico e o guarda de atribuicao em avaliar(), nao o comprimento.
    return {c for c in cands
            if c and c not in GENERICOS and len(c) > 2 and re.fullmatch(r"[a-z0-9._-]+", c)}


def consultar(produto):
    os.makedirs(CACHE, exist_ok=True)
    cam = os.path.join(CACHE, produto.replace("/", "__") + ".json")
    if os.path.exists(cam):
        return json.load(open(cam, encoding="utf-8")), True
    vms = f"cpe:2.3:a:*:{produto}:*:*:*:*:*:*:*:*"
    for tent in range(4):
        try:
            r = requests.get(BASE, params={"virtualMatchString": vms,
                                           "resultsPerPage": 200},
                             timeout=90, headers={"User-Agent": "mdcc-research"})
            if r.status_code == 200:
                d = r.json()
                json.dump(d, open(cam, "w", encoding="utf-8"), ensure_ascii=False)
                return d, False
            if r.status_code in (403, 429, 503):
                time.sleep(15 * (tent + 1))
                continue
            return {"totalResults": 0, "vulnerabilities": [], "_http": r.status_code}, False
        except Exception:
            time.sleep(10 * (tent + 1))
    return {"totalResults": 0, "vulnerabilities": [], "_erro": True}, False


def avaliar(d, slug):
    """Split the returned CVEs into accepted and doubtful, with the reason."""
    ok, duv = {}, {}
    alvo = "github.com/" + slug.lower()
    for v in d.get("vulnerabilities", []):
        cve = v["cve"]
        cid = cve["id"]
        refs = [(x.get("url") or "").lower() for x in cve.get("references", [])]
        vendors = set()
        for cfg in cve.get("configurations", []):
            for no in cfg.get("nodes", []):
                for m in no.get("cpeMatch", []):
                    p = (m.get("criteria") or "").split(":")
                    if len(p) > 4:
                        vendors.add(p[3].lower())
        if any(alvo in u for u in refs):
            ok[cid] = "referencia aponta para o repo"
        elif vendors & VENDORS_OK:
            ok[cid] = "vendor CPE = " + ",".join(sorted(vendors & VENDORS_OK))
        else:
            duv[cid] = "vendors: " + ",".join(sorted(vendors)[:4])
    return ok, duv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--censo", default="dados/fase2_2026-09-18.csv")
    ap.add_argument("--saida", default="dados/censo_cpe_nvd.csv")
    ap.add_argument("--so-com-cve", action="store_true",
                    help="varre apenas os repos que o censo GHSA ja marca com CVE")
    a = ap.parse_args()

    linhas = list(csv.DictReader(open(a.censo, encoding="utf-8-sig")))
    if a.so_com_cve:
        linhas = [l for l in linhas if (l["n_cves"] or "0").isdigit() and int(l["n_cves"]) > 0]

    produtos = {}
    for l in linhas:
        for p in produto_de(l["slug"], l.get("nome", "")):
            produtos.setdefault(p, []).append(l["slug"])
    print(f"{len(linhas)} repos -> {len(produtos)} nomes de produto a consultar")

    achados, duvidosos = {}, {}
    for i, (prod, slugs) in enumerate(sorted(produtos.items()), 1):
        d, veio_do_cache = consultar(prod)
        tot = d.get("totalResults", 0)
        for slug in set(slugs):
            ok, duv = avaliar(d, slug)
            if ok:
                achados.setdefault(slug, {}).update(ok)
            if duv:
                duvidosos.setdefault(slug, {}).update(duv)
        marca = "" if veio_do_cache else " *"
        if tot:
            print(f"  [{i}/{len(produtos)}] {prod:34s} NVD={tot:3d}{marca}")
        if not veio_do_cache:
            time.sleep(PAUSA)

    with io.open(a.saida, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["slug", "cve", "aceito", "motivo"])
        for slug, cves in sorted(achados.items()):
            for c, m in sorted(cves.items()):
                w.writerow([slug, c, "sim", m])
        for slug, cves in sorted(duvidosos.items()):
            for c, m in sorted(cves.items()):
                if c not in achados.get(slug, {}):
                    w.writerow([slug, c, "nao", m])

    n_ok = sum(len(v) for v in achados.values())
    n_du = sum(len(v) for v in duvidosos.values())
    print(f"\nACEITAS : {n_ok} CVEs em {len(achados)} repos")
    print(f"duvidosas: {n_du} (nao merjadas; ver coluna aceito=nao)")
    print(f"-> {a.saida}")


if __name__ == "__main__":
    main()
