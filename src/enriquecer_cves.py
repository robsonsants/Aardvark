#!/usr/bin/env python3
"""Enriquece as CVEs do censo com CVSS e CWE, e testa se isso prevê propagação.

Por que existe: o workflow de Damasceno et al. (SBSeg 2026) tem um passo de
enriquecimento (o Step 4 deles) que produz severidade e categoria de fraqueza.
Aqui o dado é reaproveitado com outra finalidade: em vez de caracterizar o
ecossistema (a RQ2 deles), ele entra como COVARIÁVEL da propagação — pergunta
que eles não podem responder porque não verificam forks.

Nenhuma chamada de rede: tudo sai de cache_cpe_nvd/ (respostas do NVD) e de
cache_fase2/ (advisories do GitHub), já coletados.

    python enriquecer_cves.py                      # gera cves_enriquecidas.csv
    python enriquecer_cves.py --run <pasta>        # + análise contra os vereditos
"""
import argparse, collections, csv, glob, io, json, math, os, re, sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ORD = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def ano(cve):
    m = re.match(r"CVE-(\d{4})-", cve or "")
    return int(m.group(1)) if m else 0


def carregar_censo(censo_csv, cpe_csv):
    """CVEs aceitas no censo, com o repositório de origem."""
    cves = {}
    if os.path.exists(censo_csv):
        for r in csv.DictReader(open(censo_csv, encoding="utf-8-sig")):
            for c in (r["cves"] or "").split(";"):
                if c:
                    cves.setdefault(c, r["slug"])
    if os.path.exists(cpe_csv):
        for r in csv.DictReader(open(cpe_csv, encoding="utf-8-sig"), delimiter=";"):
            if r["aceito"] == "sim":
                cves.setdefault(r["cve"], r["slug"])
    return cves


def carregar_metadados():
    """CVE -> cvss, severidade, CWEs. NVD tem prioridade sobre GHSA."""
    meta = {}
    for f in glob.glob(os.path.join("dados", "cache_cpe_nvd", "*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for v in (d.get("vulnerabilities") or []):
            c = v["cve"]
            cid = c["id"]
            if cid in meta:
                continue
            score = sev = None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mm = (c.get("metrics") or {}).get(k)
                if mm:
                    cd = mm[0].get("cvssData", {})
                    score = cd.get("baseScore")
                    sev = cd.get("baseSeverity") or mm[0].get("baseSeverity")
                    break
            cwes = sorted({x["value"] for w in (c.get("weaknesses") or [])
                           for x in w.get("description", []) if x["value"].startswith("CWE-")})
            meta[cid] = {"cvss": score, "sev": sev, "cwes": cwes, "fonte": "nvd"}
    for f in glob.glob(os.path.join("dados", "cache_fase2", "*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for it in ((d.get("advisories") or {}).get("itens") or []):
            cid = it.get("cve")
            if not cid or cid in meta:
                continue
            meta[cid] = {"cvss": it.get("cvss"),
                         "sev": (it.get("severidade") or "").upper() or None,
                         "cwes": [c for c in (it.get("cwes") or []) if c],
                         "fonte": "ghsa"}
    return meta


def norm_sev(s):
    if not s:
        return None
    s = s.upper()
    return "MEDIUM" if s == "MODERATE" else s


def pearson(xs, ys):
    if len(xs) < 4:
        return None
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    num = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    den = math.sqrt(sum((a - mx) ** 2 for a in xs) * sum((b - my) ** 2 for b in ys))
    return num / den if den else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--censo", default="dados/fase2_2026-09-18.csv")
    ap.add_argument("--cpe", default="dados/censo_cpe_nvd.csv")
    ap.add_argument("--saida", default="dados/cves_enriquecidas.csv")
    ap.add_argument("--run", default=None, help="pasta do run para cruzar com os vereditos")
    a = ap.parse_args()

    censo = carregar_censo(a.censo, a.cpe)
    meta = carregar_metadados()

    linhas = []
    for cid, slug in sorted(censo.items()):
        m = meta.get(cid) or {}
        linhas.append({"cve": cid, "repo": slug, "ano": ano(cid),
                       "cvss": m.get("cvss") or "", "severidade": norm_sev(m.get("sev")) or "",
                       "cwes": ";".join(m.get("cwes") or []), "fonte": m.get("fonte") or ""})
    with io.open(a.saida, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "repo", "ano", "cvss", "severidade", "cwes", "fonte"],
                           delimiter=";")
        w.writeheader()
        w.writerows(linhas)

    com_sev = sum(1 for l in linhas if l["severidade"])
    com_cwe = sum(1 for l in linhas if l["cwes"])
    print("CVEs do censo            : %d" % len(linhas))
    print("  com severidade         : %d (%.0f%%)" % (com_sev, 100.0 * com_sev / len(linhas)))
    print("  com CWE                : %d (%.0f%%)" % (com_cwe, 100.0 * com_cwe / len(linhas)))
    print("  fonte                  : %s" % dict(collections.Counter(l["fonte"] for l in linhas if l["fonte"])))
    print("-> %s" % a.saida)

    cw = collections.Counter()
    for l in linhas:
        for c in (l["cwes"] or "").split(";"):
            if c:
                cw[c] += 1
    print("\nCWE mais frequentes no ecossistema:")
    for c, n in cw.most_common(8):
        print("   %-12s %d" % (c, n))

    if not a.run:
        return

    ver = json.load(open(os.path.join(a.run, "dissertation_veredictos.json"), encoding="utf-8"))
    idx = {l["cve"]: l for l in linhas}

    def bloco(titulo, pares):
        g = collections.defaultdict(collections.Counter)
        for v in pares:
            s = (idx.get(v["cve_id"]) or {}).get("severidade")
            if s:
                g[s][v["status"]] += 1
        print("\n" + titulo)
        print("  %-10s %6s %8s %8s %9s" % ("sev", "pares", "CORRIG", "aval.", "%corrig"))
        for b in ORD:
            c = g.get(b)
            if not c:
                continue
            n = sum(c.values())
            aval = n - c["FILE_NOT_FOUND"]
            pct = 100.0 * c["CORRIGIDO"] / aval if aval else 0
            print("  %-10s %6d %8d %8d %8.1f%%" % (b, n, c["CORRIGIDO"], aval, pct))

    print("\n" + "=" * 68)
    print("SEVERIDADE x PROPAGACAO")
    print("=" * 68)
    bloco("AGREGADO", ver)
    bloco("CVEs ATE 2022 (codigo distante do patch)", [v for v in ver if ano(v["cve_id"]) <= 2022])
    bloco("CVEs DE 2023 EM DIANTE", [v for v in ver if ano(v["cve_id"]) >= 2023])

    porcve = collections.defaultdict(collections.Counter)
    for v in ver:
        porcve[v["cve_id"]][v["status"]] += 1
    xs, ys, xa = [], [], []
    for cid, c in porcve.items():
        sc = (idx.get(cid) or {}).get("cvss")
        aval = sum(c.values()) - c["FILE_NOT_FOUND"]
        if sc and aval:
            xs.append(float(sc))
            ys.append(100.0 * c["CORRIGIDO"] / aval)
            xa.append(ano(cid))
    r = pearson(xs, ys)
    ra = pearson(xa, ys)
    print("\n" + "=" * 68)
    print("CORRELACAO (por CVE, n=%d)" % len(xs))
    print("=" * 68)
    print("  CVSS  x cobertura : r = %+.3f   %s" % (r, "sem relacao" if abs(r) < 0.3 else "relacao detectavel"))
    print("  ano   x cobertura : r = %+.3f   %s" % (ra, "sem relacao" if abs(ra) < 0.3 else "relacao detectavel"))
    print("\n  Leitura: se o ano correlaciona e o CVSS nao, a severidade nao e o que")
    print("  governa a propagacao — a idade da CVE e.")


if __name__ == "__main__":
    main()
