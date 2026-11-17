"""
tempo_correcao.py — Quanto tempo cada fork levou para adotar a correcao do upstream.

Responde a pergunta que o lag de `dataset_temporal.py` nao responde: o lag usa o
historico do GitHub filtrado por caminho, que poda merges (ver HISTORICO_PROJETO.md).
Aqui a medida vem do grafo do git:

  * PROPAGACAO (fork existia antes do fix): procura o fix commit no historico do
    fork. Se e ancestral do HEAD do fork, a data de adocao e a do PRIMEIRO commit
    do proprio fork (nao alcancavel pelo upstream) na cadeia first-parent que ja o
    contem — tipicamente o merge "sync upstream". Se nao e ancestral, procura
    cherry-pick (trailer "cherry picked from commit <sha>" ou mesmo assunto).
  * Vulneraveis (veredito humano): censura a direita, exposicao = hoje - data do fix.

Usa clones TREELESS (--filter=tree:0), um repositorio bare por upstream com os forks
como remotes, entao so os commits sao baixados.

Uso:
  python tempo_correcao.py --run resultados/matrix/top10 [--cache DIR]
Le: dataset_temporal.json, dissertation_veredictos.json, auditoria_manual_preenchida.csv
Grava: tempo_correcao.csv e tempo_correcao.json na pasta do run.
"""
import argparse, csv, json, os, statistics, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r


def default_branch(url):
    r = subprocess.run(["git", "ls-remote", "--symref", url, "HEAD"], capture_output=True, text=True)
    for linha in r.stdout.splitlines():
        if linha.startswith("ref:"):
            return linha.split()[1].replace("refs/heads/", "")
    return None


def iso(d):
    return datetime.strptime(d, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def dias(a, b):
    return round((a - b).total_seconds() / 86400.0, 1)


def preparar(repo, upstream, forks):
    """Repositorio bare treeless com upstream e forks como remotes."""
    if not (repo / "HEAD").exists():
        repo.mkdir(parents=True, exist_ok=True)
        git(repo, "init", "--bare", "-q")
    nomes = {}
    for i, nome in enumerate([upstream] + sorted(forks)):
        rem = "up" if i == 0 else f"f{i}"
        nomes[nome] = rem
        url = f"https://github.com/{nome}.git"
        if git(repo, "remote", "get-url", rem, check=False).returncode != 0:
            git(repo, "remote", "add", rem, url)
            git(repo, "config", f"remote.{rem}.promisor", "true")
            git(repo, "config", f"remote.{rem}.partialclonefilter", "tree:0")
        br = default_branch(url)
        if not br:
            print(f"    !! sem default branch: {nome}")
            continue
        if git(repo, "rev-parse", "-q", "--verify", f"refs/remotes/{rem}/HEAD", check=False).returncode != 0:
            print(f"    fetch {nome} ({br})")
            git(repo, "fetch", "-q", "--filter=tree:0", rem, f"+refs/heads/{br}:refs/remotes/{rem}/HEAD")
    return nomes


def tem_commit(repo, sha):
    return git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def adocao(repo, rem_fork, sha):
    """(data, commit, via) da adocao do fix no fork, ou None."""
    head = f"refs/remotes/{rem_fork}/HEAD"
    if not tem_commit(repo, sha):
        git(repo, "fetch", "-q", "--filter=tree:0", "up", sha, check=False)
    if tem_commit(repo, sha) and git(repo, "merge-base", "--is-ancestor", sha, head, check=False).returncode == 0:
        # commits proprios do fork na cadeia first-parent, do mais novo ao mais antigo
        proprios = git(repo, "rev-list", "--first-parent", head, "--not", "refs/remotes/up/HEAD").stdout.split()
        if not proprios:
            return None, None, "ancestral_sem_commit_proprio"
        # contem o fix e monotono ao longo da cadeia: busca binaria pelo mais antigo que contem
        lo, hi, achado = 0, len(proprios) - 1, None
        while lo <= hi:
            m = (lo + hi) // 2
            if git(repo, "merge-base", "--is-ancestor", sha, proprios[m], check=False).returncode == 0:
                achado, lo = proprios[m], m + 1
            else:
                hi = m - 1
        if achado:
            d = git(repo, "show", "-s", "--format=%cI", achado).stdout.strip()
            return d, achado, "merge_ou_rebase"
        return None, None, "ancestral_sem_commit_proprio"
    # cherry-pick: trailer ou mesmo assunto, entre os commits proprios do fork
    assunto = git(repo, "show", "-s", "--format=%s", sha, check=False).stdout.strip() if tem_commit(repo, sha) else ""
    log = git(repo, "log", head, "--not", "refs/remotes/up/HEAD", "--format=%H%x1f%cI%x1f%s%x1f%b%x1e",
              check=False).stdout
    melhor = None
    for reg in log.split("\x1e"):
        partes = reg.strip("\n").split("\x1f")
        if len(partes) < 4:
            continue
        h, d, s, b = partes
        if f"cherry picked from commit {sha}" in b or (assunto and s.strip() == assunto):
            if melhor is None or d < melhor[0]:
                melhor = (d, h)
    if melhor:
        return melhor[0], melhor[1], "cherry_pick"
    return None, None, "nao_encontrado_no_grafo"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--cache", default="repos_git")
    args = ap.parse_args()
    base, cache = Path(args.run), Path(args.cache)
    hoje = datetime.now(timezone.utc)

    t = json.load(open(base / "dataset_temporal.json", encoding="utf-8"))
    ver = {(v["fork"], v["cve_id"]): v for v in json.load(open(base / "dissertation_veredictos.json", encoding="utf-8"))}
    hum = {r["par_id"]: r["veredito_humano"] for r in csv.DictReader(
        open(base / "auditoria_manual_preenchida.csv", encoding="utf-8-sig"), delimiter=";")}

    fixes, criado, up_de = {}, {}, {}
    for p in t["pares"]:
        k = (p["fork"], p["cve_id"])
        if p["data_fix_upstream"]:
            fixes.setdefault(k, {})[p["fix_sha"]] = p["data_fix_upstream"]
        criado[p["fork"]] = p["fork_created_at"]
        up_de[p["fork"]] = p["upstream"]

    pares = sorted(k for k in fixes
                   if ver.get(k, {}).get("status") not in (None, "FILE_NOT_FOUND")
                   and criado.get(k[0]) and criado[k[0]] <= min(fixes[k].values()))
    print(f"{len(pares)} pares de propagacao verificaveis")

    por_up = {}
    for f, _ in pares:
        por_up.setdefault(up_de[f], set()).add(f)

    linhas = []
    for up, forks in sorted(por_up.items()):
        repo = cache / up.replace("/", "__")
        print(f"\n[{up}] {len(forks)} forks")
        nomes = preparar(repo, up, forks)
        for f, cve in [k for k in pares if k[0] in forks]:
            h = hum.get(f"{f}::{cve}", "?")
            melhores = []
            for sha, dfix in fixes[(f, cve)].items():
                d, c, via = adocao(repo, nomes[f], sha)
                melhores.append((d, c, via, sha, dfix))
            achados = [m for m in melhores if m[0]]
            d_fix = min(m[4] for m in melhores)
            if achados:
                d, c, via, sha, dfix_sel = min(achados, key=lambda m: m[0])
                dd = datetime.fromisoformat(d.replace("Z", "+00:00"))
                tempo = dias(dd, iso(dfix_sel))
            else:
                d, c, via, sha, dfix_sel = None, None, melhores[0][2], melhores[0][3], d_fix
                tempo = None
            expo = dias(hoje, iso(d_fix)) if tempo is None else None
            linhas.append({
                "fork": f, "upstream": up, "cve_id": cve, "veredito_humano": h,
                "veredito_uniao": ver[(f, cve)]["status"], "fix_sha": sha, "data_fix": dfix_sel,
                "fork_criado": criado[f], "via": via, "commit_adocao": c, "data_adocao": d,
                "dias_ate_corrigir": tempo, "dias_exposto_ate_hoje": expo,
            })
            print(f"    {f:<42} {cve:<16} humano={h:<10} {via:<26} "
                  f"{(str(tempo) + ' d') if tempo is not None else ('exposto ' + str(expo) + ' d')}")

    with open(base / "tempo_correcao.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(linhas[0].keys()), delimiter=";")
        w.writeheader(); w.writerows(linhas)

    corr = [l["dias_ate_corrigir"] for l in linhas if l["dias_ate_corrigir"] is not None and l["veredito_humano"] == "CORRIGIDO"]
    expo = [l["dias_exposto_ate_hoje"] for l in linhas if l["veredito_humano"] == "VULNERAVEL"]
    def resumo(v):
        if not v:
            return None
        q = statistics.quantiles(v, n=4) if len(v) > 1 else [v[0]] * 3
        return {"n": len(v), "mediana": round(statistics.median(v), 1), "q1": round(q[0], 1),
                "q3": round(q[2], 1), "min": min(v), "max": max(v)}
    out = {"run": str(base), "gerado_em": hoje.isoformat(), "n_pares": len(linhas),
           "corrigidos_com_data": resumo(corr),
           "vulneraveis_exposicao": resumo(expo),
           "via": {v: sum(1 for l in linhas if l["via"] == v) for v in {l["via"] for l in linhas}},
           "pares": linhas}
    json.dump(out, open(base / "tempo_correcao.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\n-> {base / 'tempo_correcao.csv'}\n-> {base / 'tempo_correcao.json'}")
    print("Corrigidos (humano) com data de adocao:", out["corrigidos_com_data"])
    print("Vulneraveis (humano), dias expostos ate hoje:", out["vulneraveis_exposicao"])
    print("Via:", out["via"])


if __name__ == "__main__":
    main()
