# -*- coding: utf-8 -*-
"""
Scales the embedding ranker (UniXcoder) to the WHOLE mined ecosystem -- every CVE x
fork across the 5 categories (synapse/Python, matrix-rust-sdk/Rust,
element-android/Kotlin, matrix-hookshot/TS, matrix-appservice-irc/TS) -- and compares
it head to head with the baselines (hash, AST, AST dual reference) against the
ground truth.

Function extraction via tree-sitter (treesit_extract); the reference is the diff
SNIPPET restricted to the target function; alignment by sliding window, with patch
presence scored as an independent maximum over the vulnerable and patched references.

Output: resultados_YYYY-MM-DD/{ecossistema_embeddings.json, RESUMO.md}.
"""
import sys, os, json, base64, time, re, datetime
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass
import requests
from unixcoder_embed import UniXcoder, cos
import treesit_extract as tse

MARGIN = 0.02
RESULTS = os.path.join(PROJ, "resultados_2026-07-04", "dissertation_resultados.json")
GT_METRICS = os.path.join(PROJ, "resultados_2026-07-04", "gt_dissertation_metricas.json")
EXT_LANG = {".py": "python", ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin",
            ".ts": "typescript", ".tsx": "tsx", ".js": "typescript",
            ".swift": "swift", ".go": "go"}


def read_token():
    for line in open(os.path.join(PROJ, ".env"), encoding="utf-8", errors="ignore"):
        line = line.strip()
        if line.startswith("GITHUB_TOKEN="):
            return line.split("=", 1)[1].strip()
        if line.lower().startswith("token ") and "ghp_" in line:
            return line.split()[-1]
    return os.getenv("GITHUB_TOKEN", "")


S = requests.Session()
S.headers.update({"Authorization": f"token {read_token()}",
                  "Accept": "application/vnd.github+json"})
_FILE_CACHE, _COMMIT_CACHE = {}, {}


def api(url, params=None):
    for i in range(3):
        try:
            r = S.get(url, params=params, timeout=25)
        except Exception:
            time.sleep(2 * (i + 1)); continue
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return None
        time.sleep(2 * (i + 1))
    return None


def get_file(repo, path, ref=None):
    key = (repo, path, ref)
    if key in _FILE_CACHE:
        return _FILE_CACHE[key]
    j = api(f"https://api.github.com/repos/{repo}/contents/{path}",
            params={"ref": ref} if ref else None)
    out = base64.b64decode(j["content"]).decode("utf-8", "replace") if j and "content" in j else None
    _FILE_CACHE[key] = out
    return out


def get_commit(repo, sha):
    if sha in _COMMIT_CACHE:
        return _COMMIT_CACHE[sha]
    _COMMIT_CACHE[sha] = api(f"https://api.github.com/repos/{repo}/commits/{sha}")
    return _COMMIT_CACHE[sha]


def diff_events(patch):
    ev, p, q = [], 0, 0
    for ln in patch.splitlines():
        h = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", ln)
        if h:
            p, q = int(h.group(1)), int(h.group(2)); continue
        if ln.startswith(("+++", "---")):
            continue
        if ln.startswith("-"):
            ev.append(("-", p, None, ln[1:])); p += 1
        elif ln.startswith("+"):
            ev.append(("+", None, q, ln[1:])); q += 1
        else:
            ev.append((" ", p, q, ln[1:] if ln.startswith(" ") else "")); p += 1; q += 1
    return ev


def region_snippets(events, pre_rng, post_rng):
    pre, post = [], []
    ps, pe = pre_rng; qs, qe = post_rng
    for t, p, q, txt in events:
        if t == "-" and p is not None and ps <= p <= pe:
            pre.append(txt)
        elif t == "+" and q is not None and qs <= q <= qe:
            post.append(txt)
        elif t == " ":
            if p is not None and ps <= p <= pe:
                pre.append(txt)
            if q is not None and qs <= q <= qe:
                post.append(txt)
    return "\n".join(pre).strip(), "\n".join(post).strip()


def windows(code, win=16, stride=8, cap=160):
    lines = code.splitlines()
    if len(lines) <= win:
        return [code]
    ws = ["\n".join(lines[a:a + win]) for a in range(0, len(lines) - win + 1, stride)]
    ws.append("\n".join(lines[-win:]))
    if len(ws) > cap:
        step = len(ws) / cap
        ws = [ws[int(i * step)] for i in range(cap)]
    return ws


def score(fn_code, ev, ep, model):
    sv = sp = -1.0
    for w in windows(fn_code):
        e = model.embed(w)
        sv = max(sv, cos(e, ev)); sp = max(sp, cos(e, ep))
    return (sv, sp) if sv > -1.0 else (0.0, 0.0)


def verdict(sv, sp):
    d = sp - sv
    if d > MARGIN:
        return "CORRIGIDO", d
    if d < -MARGIN:
        return "VULNERAVEL", d
    return "ZONA_INCERTEZA", d


def lang_of(path, fallback):
    return EXT_LANG.get(os.path.splitext(path)[1].lower(), fallback)


def build_refs(upstream, fix_sha, path, lang, model):
    """Retorna (target_name, ev, ep, sanity, pre_file, post_file) ou None."""
    commit = get_commit(upstream, fix_sha)
    if not commit or not commit.get("parents"):
        return None
    parent = commit["parents"][0]["sha"]
    patch = None
    for f in commit.get("files", []):
        if f.get("filename") == path and f.get("patch"):
            patch = f["patch"]; break
    if not patch:
        return None
    pre_file = get_file(upstream, path, parent)
    post_file = get_file(upstream, path, fix_sha)
    if not pre_file or not post_file:
        return None
    events = diff_events(patch)
    post_changed = [q for t, p, q, _ in events if t == "+" and q is not None]
    cnt = Counter()
    for q in post_changed:
        fn = tse.enclosing_function(post_file, lang, q - 1)
        if fn and fn["name"]:
            cnt[fn["name"]] += 1
    target = cnt.most_common(1)[0][0] if cnt else None
    pf = tse.function_by_name(pre_file, lang, target) if target else None
    qf = tse.function_by_name(post_file, lang, target) if target else None
    if pf and qf:
        vuln_ref, patch_ref = region_snippets(events,
                                              (pf["start"] + 1, pf["end"] + 1),
                                              (qf["start"] + 1, qf["end"] + 1))
        vuln_ref = vuln_ref or pf["text"]
        patch_ref = patch_ref or qf["text"]
    else:  # fallback: todo o diff
        vr, pr = region_snippets(events, (0, 10**9), (0, 10**9))
        vuln_ref, patch_ref = vr or pre_file, pr or post_file
    ev, ep = model.embed(vuln_ref), model.embed(patch_ref)
    return target, ev, ep, round(cos(ev, ep), 3), pre_file, post_file


def main():
    rows = json.load(open(RESULTS, encoding="utf-8"))
    gt = {p["chave"] for p in json.load(open(GT_METRICS, encoding="utf-8"))["pares"]}

    # baselines por par (union) a partir dos sinais já gravados
    base = defaultdict(lambda: {"hash": False, "ast": False, "dual": False})
    for r in rows:
        k = f"{r['upstream']}::{r['fork']}::{r['cve_id']}"
        if r.get("sha_match"):
            base[k]["hash"] = True
        if r.get("label_2a") == "CORRIGIDO":
            base[k]["ast"] = True
        if r.get("label_2b") == "CORRIGIDO":
            base[k]["dual"] = True

    # tarefas: (upstream, cve, fix_sha, filepath) presentes no dataset
    tasks = {}
    for r in rows:
        if r.get("status") == "FILE_NOT_FOUND" or not r.get("filepath"):
            continue
        key = (r["upstream"], r["cve_id"], r["fix_sha"], r["filepath"])
        tasks.setdefault(key, {"lang": lang_of(r["filepath"], r.get("language", "")),
                               "forks": set()})["forks"].add(r["fork"])

    print("Carregando UniXcoder...")
    model = UniXcoder()

    pair_emb = defaultdict(str)          # (upstream::fork::cve) -> melhor veredito (union)
    STPRI = {"CORRIGIDO": 3, "VULNERAVEL": 2, "ZONA_INCERTEZA": 1, "SEM_FUNCAO": 0, "": -1}
    detail, sanity_log = [], []
    for (upstream, cve, fix_sha, path), info in sorted(tasks.items()):
        lang = info["lang"]
        refs = build_refs(upstream, fix_sha, path, lang, model)
        if not refs:
            continue
        target, ev, ep, sanity, pre_file, post_file = refs
        # sanidade upstream
        for tag, content in [("pre", pre_file), ("fix", post_file)]:
            fn = tse.function_by_name(content, lang, target) if target else None
            sv, sp = score(fn["text"] if fn else content, ev, ep, model)
            sanity_log.append({"cve": cve, "file": path, "lado": tag,
                               "veredito": verdict(sv, sp)[0], "sanity": sanity})
        for fork in sorted(info["forks"]):
            src = get_file(fork, path)
            if not src:
                st = "SEM_FUNCAO"; sv = sp = None
            else:
                fn = tse.function_by_name(src, lang, target) if target else None
                sv, sp = score(fn["text"] if fn else src, ev, ep, model)
                st = verdict(sv, sp)[0]
            k = f"{upstream}::{fork}::{cve}"
            if STPRI[st] > STPRI[pair_emb[k] or ""]:
                pair_emb[k] = st
            detail.append({"upstream": upstream, "fork": fork, "cve": cve, "file": path,
                           "lang": lang, "target": target,
                           "sim_vuln": round(sv, 3) if sv is not None else None,
                           "sim_corrigido": round(sp, 3) if sp is not None else None,
                           "veredito": st})

    # métricas vs ground truth (34 pares conclusivos, todos CONFIRMED_PATCHED)
    def tp(pred):
        return sum(1 for k in gt if pred(k))
    m_hash = tp(lambda k: base[k]["hash"])
    m_ast = tp(lambda k: base[k]["ast"])
    m_dual = tp(lambda k: base[k]["dual"])
    m_emb = tp(lambda k: pair_emb.get(k) == "CORRIGIDO")
    n = len(gt)
    resolved = sorted(k for k in gt if pair_emb.get(k) == "CORRIGIDO" and not base[k]["ast"])

    headline = {
        "n_gt_conclusivos": n,
        "recall": {
            "hash_wyss": round(m_hash / n, 3), "ast_vercation": round(m_ast / n, 3),
            "dualref_pptfi": round(m_dual / n, 3), "embeddings_unixcoder": round(m_emb / n, 3),
        },
        "TP": {"hash": m_hash, "ast": m_ast, "dualref": m_dual, "embeddings": m_emb},
        "falsos_negativos_da_AST_resolvidos_por_embeddings": len(resolved),
        "pares_resolvidos": resolved,
    }
    out = {"headline": headline, "sanity_upstream": sanity_log, "detalhe_pares": detail}
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          f"resultados_{datetime.date.today().isoformat()}")
    os.makedirs(outdir, exist_ok=True)
    json.dump(out, open(os.path.join(outdir, "ecossistema_embeddings.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print("\n================ RECALL vs GROUND TRUTH (34 pares) ================")
    print(f"  hash (Wyss)            : {m_hash:>2}/{n}  recall={m_hash/n:.3f}")
    print(f"  AST  (VERCATION)       : {m_ast:>2}/{n}  recall={m_ast/n:.3f}")
    print(f"  dupla-ref (PPTFI)      : {m_dual:>2}/{n}  recall={m_dual/n:.3f}")
    print(f"  embeddings (UniXcoder) : {m_emb:>2}/{n}  recall={m_emb/n:.3f}")
    print(f"  -> falsos negativos da AST resolvidos por embeddings: {len(resolved)}")
    sane = sum(1 for s in sanity_log if (s["lado"] == "pre" and s["veredito"] == "VULNERAVEL")
               or (s["lado"] == "fix" and s["veredito"] == "CORRIGIDO"))
    print(f"  sanidade upstream OK   : {sane}/{len(sanity_log)}")
    print(f"-> {os.path.join(outdir, 'ecossistema_embeddings.json')}")
    return out, outdir


if __name__ == "__main__":
    main()
