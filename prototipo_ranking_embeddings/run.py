# -*- coding: utf-8 -*-
"""
Prototype -- embedding-based search/ranking (UniXcoder) on the SERVER leg (synapse).

Implements the ranked-search pipeline end to end on a single CVE:
  1. take an upstream CVE (synapse) and its fix commit;
  2. locate the changed METHOD from the git hunk headers and extract the changed
     SNIPPET (the diff region): VULNERABLE image (pre) and PATCHED image (post);
  3. for each downstream fork, extract the SAME method (class::name) and slide a small
     window inside it (without truncating) to find the aligned region;
  4. QUERY = vulnerable snippet -> RANK the forks by similarity;
  5. verdict by semantic DUAL REFERENCE: is the fork's aligned window closer to the
     VULNERABLE or to the PATCHED snippet? (the semantic analogue of Layer 2B).

Three refinements over the naive approach: the target is a METHOD (not a whole class),
the reference is the diff SNIPPET (not the entire function), and a sliding WINDOW runs
inside the method -- which avoids UniXcoder's 512-token truncation on large functions.
"""
import sys, os, json, base64, time, re, datetime, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass
import requests
from unixcoder_embed import UniXcoder, cos

MARGIN = 0.02
UPSTREAM = "element-hq/synapse"
FORKS = ["microchipster/synapse", "kakahu2015/synapse", "shcherbak/synapse"]
CVES = {
    "CVE-2024-31208": ("55b0aa847a61774b6a3acdc4b177a20dc019f01a",
                       "synapse/storage/databases/main/events.py",
                       "GT=CONFIRMED_PATCHED nos 3 forks; AST=ZONA_INCERTEZA (falsos negativos)"),
    "CVE-2025-61672": ("26aaaf9e48fff80cf67a20c691c75d670034b3c1",
                       "synapse/rest/client/keys.py",
                       "GT inconclusivo no experimento anterior"),
}
DEF_RE = r"^(\s*)(async\s+def|def|class)\s+(\w+)"


def read_token():
    p = os.path.join(PROJ, ".env")
    for line in open(p, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if line.startswith("GITHUB_TOKEN="):
            return line.split("=", 1)[1].strip()
        if line.lower().startswith("token ") and "ghp_" in line:
            return line.split()[-1]
    return os.getenv("GITHUB_TOKEN", "")


S = requests.Session()
S.headers.update({"Authorization": f"token {read_token()}",
                  "Accept": "application/vnd.github+json"})


def api(url, params=None):
    for i in range(3):
        r = S.get(url, params=params, timeout=25)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return None
        time.sleep(2 * (i + 1))
    return None


def get_file(repo, path, ref=None):
    j = api(f"https://api.github.com/repos/{repo}/contents/{path}",
            params={"ref": ref} if ref else None)
    if not j or "content" not in j:
        return None
    return base64.b64decode(j["content"]).decode("utf-8", "replace")


# ---------- estrutura de código ----------
def iter_defs(src):
    lines = (src or "").splitlines()
    defs = []
    for i, l in enumerate(lines):
        m = re.match(DEF_RE, l)
        if m:
            indent = len(m.group(1))
            # pular a assinatura (pode ser multilinha em synapse: `def f(\n ...\n) -> T:`)
            j, depth = i, 0
            while j < len(lines):
                depth += lines[j].count("(") - lines[j].count(")")
                if depth <= 0 and lines[j].rstrip().endswith(":"):
                    j += 1
                    break
                j += 1
            # corpo até dedent
            while j < len(lines):
                lj = lines[j]
                if lj.strip() and (len(lj) - len(lj.lstrip())) <= indent:
                    break
                j += 1
            defs.append({"indent": indent, "kind": m.group(2).strip(),
                         "name": m.group(3), "start": i, "end": j})
    return defs, lines


def enclosing_class(defs, start):
    best = None
    for d in defs:
        if d["kind"] == "class" and d["start"] < start < d["end"]:
            if best is None or d["indent"] > best["indent"]:
                best = d
    return best["name"] if best else None


def occurrences(src, name):
    """(classe|None, kind, código) para cada definição de `name`."""
    defs, lines = iter_defs(src)
    return [(enclosing_class(defs, d["start"]), d["kind"],
             "\n".join(lines[d["start"]:d["end"]]).strip())
            for d in defs if d["name"] == name]


def extract_qualified(src, cls, name):
    for c, _, code in occurrences(src, name):
        if c == cls:
            return code
    return None


def hunk_candidates(patch):
    names, seen = [], set()
    for l in patch.splitlines():
        m = re.match(r"^@@ .*? @@\s*(?:async\s+def|def|class)\s+(\w+)", l)
        if m and m.group(1) not in seen:
            seen.add(m.group(1)); names.append(m.group(1))
    return names


def hunk_snippets_for(patch, name):
    """Imagem pré (vulnerável) e pós (corrigida) apenas dos hunks do método `name`."""
    pre, post, cur = [], [], False
    for l in patch.splitlines():
        if l.startswith("@@"):
            m = re.match(r"^@@ .*? @@\s*(?:async\s+def|def|class)\s+(\w+)", l)
            cur = bool(m and m.group(1) == name)
            continue
        if not cur:
            continue
        if l.startswith("-"):
            pre.append(l[1:])
        elif l.startswith("+"):
            post.append(l[1:])
        elif l.startswith(" "):
            pre.append(l[1:]); post.append(l[1:])
    return "\n".join(pre).strip(), "\n".join(post).strip()


def choose_target(patch, pre_file, post_file, model):
    """Método (não classe) de NOME identificável, com maior mudança (menor cosseno)."""
    best = None
    for name in hunk_candidates(patch):
        pre_occ = {c: code for c, k, code in occurrences(pre_file, name) if k != "class"}
        post_occ = {c: code for c, k, code in occurrences(post_file, name) if k != "class"}
        for cls in set(pre_occ) & set(post_occ):
            s = cos(model.embed(pre_occ[cls]), model.embed(post_occ[cls]))
            if best is None or s < best[1]:
                best = ((cls, name), s)
    return best[0] if best else None


def windows(code, win=16, stride=6):
    lines = code.splitlines()
    if len(lines) <= win:
        return [code]
    out = ["\n".join(lines[a:a + win]) for a in range(0, len(lines) - win + 1, stride)]
    out.append("\n".join(lines[-win:]))
    return out


def score(fn_code, ev, ep, model):
    """Presença de patch: melhor casamento do método com CADA referência,
    independentemente -> (sim_vuln, sim_corr). sp alto = contém o código corrigido;
    sv alto = contém o código vulnerável; o delta decide o veredito."""
    sv = sp = -1.0
    for w in windows(fn_code):
        e = model.embed(w)
        sv = max(sv, cos(e, ev))
        sp = max(sp, cos(e, ep))
    return (sv, sp) if sv > -1.0 else (0.0, 0.0)


def verdict(sv, sp):
    d = sp - sv
    if d > MARGIN:
        return "CORRIGIDO", d
    if d < -MARGIN:
        return "VULNERAVEL", d
    return "ZONA_INCERTEZA", d


def process(cve, model):
    fix_sha, path, gt = CVES[cve]
    commit = api(f"https://api.github.com/repos/{UPSTREAM}/commits/{fix_sha}")
    parent = commit["parents"][0]["sha"] if commit and commit.get("parents") else None
    patch = None
    for f in (commit or {}).get("files", []):
        if f.get("filename") == path and f.get("patch"):
            patch = f["patch"]; break

    pre_file = get_file(UPSTREAM, path, parent)
    post_file = get_file(UPSTREAM, path, fix_sha)

    tgt = choose_target(patch, pre_file or "", post_file or "", model) if patch else None
    cls, name = tgt if tgt else (None, None)
    vuln_snip, patch_snip = hunk_snippets_for(patch, name) if name else ("", "")
    if not vuln_snip:
        vuln_snip = extract_qualified(pre_file or "", cls, name) or (pre_file or "")
    if not patch_snip:
        patch_snip = extract_qualified(post_file or "", cls, name) or (post_file or "")
    label = f"{cls + '::' if cls else ''}{name}"
    ev, ep = model.embed(vuln_snip), model.embed(patch_snip)
    sanity = cos(ev, ep)

    def target_code(content):
        if name:
            fn = extract_qualified(content, cls, name)
            if fn:
                return fn, "metodo"
        return content, "arquivo"

    targets = [("UPSTREAM@pre (vulnerável)", pre_file),
               ("UPSTREAM@fix (corrigido)", post_file)]
    targets += [(fk, get_file(fk, path)) for fk in FORKS]

    rows = []
    for nm, content in targets:
        if not content:
            rows.append({"alvo": nm, "status": "FILE_NOT_FOUND"})
            continue
        fn, how = target_code(content)
        sv, sp = score(fn, ev, ep, model)
        st, d = verdict(sv, sp)
        lean = "→corr" if sp > sv else ("→vuln" if sv > sp else "=")
        rows.append({"alvo": nm, "sim_vuln": round(sv, 3), "sim_corrigido": round(sp, 3),
                     "delta": round(d, 3), "status": st, "tendencia": lean, "alinhamento": how})

    forks_rows = [r for r in rows if "/synapse" in r["alvo"] and r.get("sim_vuln") is not None]
    ranking = sorted(forks_rows, key=lambda r: -r["sim_vuln"])
    return {
        "cve": cve, "arquivo": path, "alvo_metodo": label,
        "fix_sha": fix_sha, "parent_sha": parent, "margem": MARGIN,
        "trecho_vuln_linhas": vuln_snip.count("\n") + 1,
        "trecho_corrigido_linhas": patch_snip.count("\n") + 1,
        "sanity_sim_vuln_vs_corrigido": round(sanity, 3),
        "resultados": rows,
        "ranking_forks_por_sim_vuln": [r["alvo"] for r in ranking],
        "ground_truth": gt,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve", default="all")
    args = ap.parse_args()
    cves = list(CVES) if args.cve == "all" else [args.cve]

    print("Carregando UniXcoder (microsoft/unixcoder-base)...")
    model = UniXcoder()
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          f"resultados_{datetime.date.today().isoformat()}")
    os.makedirs(outdir, exist_ok=True)

    allout = []
    for cve in cves:
        res = process(cve, model)
        allout.append(res)
        print(f"\n=== {cve} — {res['arquivo']}  (alvo: {res['alvo_metodo']}) ===")
        print(f"GT: {res['ground_truth']}")
        print(f"trecho vuln->corr: {res['trecho_vuln_linhas']}->{res['trecho_corrigido_linhas']} linhas | "
              f"sanity sim(vuln,corr) = {res['sanity_sim_vuln_vs_corrigido']}")
        print(f"{'ALVO':<34}{'sim_vuln':>9}{'sim_corr':>9}{'delta':>8}   veredito")
        for r in res["resultados"]:
            if r.get("sim_vuln") is None:
                print(f"{r['alvo']:<34}{'—':>9}{'—':>9}{'—':>8}   {r['status']}")
            else:
                print(f"{r['alvo']:<34}{r['sim_vuln']:>9}{r['sim_corrigido']:>9}"
                      f"{r['delta']:>8}   {r['status']} {r['tendencia']}")
        print("ranking (query=trecho vulnerável): "
              + " > ".join(a.split('/')[0] for a in res["ranking_forks_por_sim_vuln"]))

    p = os.path.join(outdir, "ranking_embeddings_synapse.json")
    json.dump(allout, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\n-> {p}")


if __name__ == "__main__":
    main()
