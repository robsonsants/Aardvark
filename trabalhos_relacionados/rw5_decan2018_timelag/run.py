# -*- coding: utf-8 -*-
"""
rw5 — Decan et al. (2018) "Technical Lag" / Ponta et al. (2020) "Window of
      Vulnerability".  Reproduces the time-lag analysis.

REPRODUCED METHOD
  Adoption latency (time lag) = days between the date of the upstream fix COMMIT and
  the date the fork integrated that fix. "Last touch" approximation: we take the date
  of the fork's most recent commit touching the patched FILE
  (GitHub API: /commits?path=...&per_page=1). Same heuristic validated by manual
  sampling against the ground truth.

INPUT: (fork, CVE, file) pairs marked patched in dissertation_resultados.json.
NETWORK: GitHub REST API v3, authenticated with GITHUB_TOKEN (read from .env).
OUTPUT: results JSON with per-pair lag + statistics (median, min, max, extremes).
"""
import sys, os, json, time, statistics
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import load_rows, PROJ, dump_dated

try:
    import requests
except Exception:
    print("FALTA a lib 'requests' (pip install requests)."); sys.exit(1)


def read_token():
    p = os.path.join(PROJ, ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip()
            if line.lower().startswith("token ") and "ghp_" in line:
                return line.split()[-1].strip()
    return os.getenv("GITHUB_TOKEN", "")


TOKEN = read_token()
if not TOKEN:
    print("Sem GITHUB_TOKEN no .env — rw5 (time lag) precisa de rede autenticada.")
    sys.exit(2)
H = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
S = requests.Session(); S.headers.update(H)


def get_json(url, params=None, tries=3):
    for i in range(tries):
        r = S.get(url, params=params, timeout=25)
        if r.status_code == 200:
            return r.json()
        if r.status_code in (403, 429) and "rate limit" in r.text.lower():
            time.sleep(5 * (i + 1)); continue
        if r.status_code == 404:
            return None
        time.sleep(2 * (i + 1))
    return None


def commit_date(owner_repo, sha):
    j = get_json(f"https://api.github.com/repos/{owner_repo}/commits/{sha}")
    if j:
        return j["commit"]["committer"]["date"]
    return None


def last_touch_date(fork, path):
    j = get_json(f"https://api.github.com/repos/{fork}/commits",
                 params={"path": path, "per_page": 1})
    if j and isinstance(j, list) and j:
        return j[0]["commit"]["committer"]["date"]
    return None


def parse(dt):
    return datetime.fromisoformat(dt.replace("Z", "+00:00")).astimezone(timezone.utc)


rows = load_rows()
# Pares corrigidos (evidência de adoção): status CORRIGIDO ou hash idêntico.
pairs = [r for r in rows if r.get("status") == "CORRIGIDO" or r.get("sha_match")]

upstream_date = {}   # (upstream, fix_sha) -> date
lags, detail = [], []
for r in pairs:
    up, sha, fork, path, cve = r["upstream"], r["fix_sha"], r["fork"], r["filepath"], r["cve_id"]
    uk = (up, sha)
    if uk not in upstream_date:
        upstream_date[uk] = commit_date(up, sha)
    ud = upstream_date[uk]
    fd = last_touch_date(fork, path)
    if not ud or not fd:
        detail.append({"fork": fork, "cve": cve, "lag_dias": None, "motivo": "data indisponível"})
        continue
    lag = (parse(fd) - parse(ud)).days
    lags.append(lag)
    detail.append({"fork": fork, "cve": cve, "upstream": up,
                   "data_fix_upstream": ud[:10], "data_adocao_fork": fd[:10], "lag_dias": lag})

detail_ok = [d for d in detail if d["lag_dias"] is not None]
detail_ok.sort(key=lambda d: d["lag_dias"])
stats = {}
if lags:
    stats = {
        "n": len(lags), "min": min(lags), "max": max(lags),
        "mediana": statistics.median(lags),
        "media": round(statistics.mean(lags), 1),
    }

out = {
    "trabalho": "Decan et al. (2018) Technical Lag / Ponta et al. (2020) Window of Vulnerability",
    "papel_na_proposta": "Time Lag — velocidade de reação da rede (§5.4.2, Fig.6/Tab.8)",
    "metodo": "lag(dias) = data_ultimo_commit_no_arquivo(fork) - data_commit_correcao(upstream)",
    "observacao": "Aproximação de 'último toque' no arquivo do patch (mesma heurística do §5.4.2).",
    "estatisticas_dias": stats,
    "mais_ageis": detail_ok[:5],
    "maior_inercia": detail_ok[-5:][::-1],
    "detalhe": detail,
}
p = dump_dated("rw5_decan2018_timelag.json", out)
print("=== rw5 Technical Lag (Decan 2018 / Ponta 2020) ===")
print(f"Pares com lag calculado : {stats.get('n', 0)}")
if stats:
    print(f"Lag (dias) min/mediana/media/max : "
          f"{stats['min']} / {stats['mediana']} / {stats['media']} / {stats['max']}")
print(f"-> {p}")
