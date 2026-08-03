# -*- coding: utf-8 -*-
"""
CONTENT-BASED AUTOMATIC AUDIT of the negative worklist.

For each instance it checks whether the fork ADOPTED the upstream security patch --
not through structural similarity (which is what produced the disputed cases), but by
testing the PRESENCE of the fix's KEY LINES (the lines the patch ADDED/REMOVED in the
target function). Same line-based ground-truth logic used elsewhere in the project,
here automated.

Adoption signal (0..1):
  - lines ADDED by the fix present in the fork's code    -> high = adopted
  - lines REMOVED by the fix still present in the fork   -> high = NOT adopted
Veredito: score >= 0.5 -> CORRIGIDO (adotou) ; senão VULNERAVEL.

Saídas:
  - auditoria_negativos_worklist.csv  (preenche veredito_humano = auto + evidência)
  - resultados_2026-07-09/auditoria_adocao_HEAD.csv (adoção no HEAD por fork×CVE)
"""
import os, sys, json, csv, re
from collections import defaultdict, OrderedDict
from difflib import SequenceMatcher
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass
import run_ecosystem as R
import treesit_extract as tse

HERE = os.path.dirname(os.path.abspath(__file__))
WL = os.path.join(HERE, "auditoria_negativos_worklist.csv")
RESULTS = os.path.join(PROJ, "resultados_2026-07-04", "dissertation_resultados.json")


def norm(l):
    return " ".join(l.split())


def nontrivial(l):
    s = norm(l)
    if len(s) < 5:
        return False
    if s in ("{", "}", "};", "})", ");", "(", ")", "[", "]", "})."):
        return False
    if s.lstrip().startswith(("//", "#", "/*", "*", "*/")):
        return False
    return True


def present(k, hay, thr=0.85):
    return any(SequenceMatcher(None, k, h).ratio() >= thr for h in hay)


# (upstream, cve) -> [(fix_sha, filepath)]
rows = json.load(open(RESULTS, encoding="utf-8"))
cvefiles = defaultdict(list)
seen = set()
for r in rows:
    if r.get("fix_sha") and r.get("filepath"):
        t = (r["upstream"], r["cve_id"], r["fix_sha"], r["filepath"])
        if t not in seen:
            seen.add(t)
            cvefiles[(r["upstream"], r["cve_id"])].append((r["fix_sha"], r["filepath"]))

_REF_CACHE = {}


def refs_for(up, cve):
    """Do DIFF real do commit, reconstrói o HUNK mais alterado como dois blocos
    contíguos: PRÉ-imagem (contexto + linhas removidas) e PÓS-imagem (contexto +
    linhas adicionadas). O contexto compartilhado torna a comparação discriminante
    mesmo em patches pequenos (lógica da Camada 2B / dupla referência)."""
    key = (up, cve)
    if key in _REF_CACHE:
        return _REF_CACHE[key]
    result = None
    for sha, fp in cvefiles.get((up, cve), []):
        commit = R.get_commit(up, sha)
        if not commit or not commit.get("files"):
            continue
        fentry = next((f for f in commit["files"] if f["filename"] == fp), None)
        if not fentry or "patch" not in fentry:
            continue
        hunks, pre, post, nch = [], [], [], 0

        def flush():
            nonlocal pre, post, nch
            if pre or post:
                hunks.append((nch, pre, post))
            pre, post, nch = [], [], 0

        for l in fentry["patch"].splitlines():
            if l.startswith("@@"):
                flush(); continue
            if l.startswith(("+++", "---", "\\")):
                continue
            if l.startswith("+"):
                post.append(norm(l[1:])); nch += 1
            elif l.startswith("-"):
                pre.append(norm(l[1:])); nch += 1
            else:                                   # contexto (linha com ' ' ou vazia)
                c = norm(l[1:] if l[:1] == " " else l)
                pre.append(c); post.append(c)
        flush()
        if not hunks:
            continue
        nch, pre, post = max(hunks, key=lambda h: h[0])   # hunk mais alterado
        parent = commit["parents"][0]["sha"] if commit.get("parents") else None
        result = {"fp": fp, "pre_block": [x for x in pre if x],
                  "post_block": [x for x in post if x], "n_change": nch,
                  "parent": parent, "fix_date": commit["commit"]["committer"]["date"]}
        break
    _REF_CACHE[key] = result
    return result


def best_block_ratio(block, flines):
    """Melhor similaridade (SequenceMatcher) do bloco a uma janela contígua do
    arquivo. Ancorado na 1ª linha do bloco para não varrer o arquivo inteiro."""
    if not block or not flines:
        return None
    W, bt, anchor = len(block), "\n".join(block), block[0]
    cands = [i for i, fl in enumerate(flines)
             if SequenceMatcher(None, anchor, fl).ratio() > 0.6]
    if not cands:
        cands = range(0, max(1, len(flines) - W + 1))
    best, sm, seen = 0.0, SequenceMatcher(), set()
    sm.set_seq1(bt)
    for i in cands:
        wt = "\n".join(flines[i:i + W])
        if wt in seen:
            continue
        seen.add(wt)
        sm.set_seq2(wt)
        if sm.quick_ratio() <= best:
            continue
        r = sm.ratio()
        if r > best:
            best = r
    return best


def adoption(code, refs):
    """Dupla referência em nível de bloco: o código se parece mais com a PÓS-imagem
    (corrigido) ou com a PRÉ-imagem (vulnerável)? Empate/refs fracas -> escala."""
    if not code:
        return "SEM_ARQUIVO", None, ""
    flines = [norm(l) for l in code.splitlines() if l.strip()]
    sv = best_block_ratio(refs["pre_block"], flines) or 0.0     # ~ vulnerável
    sp = best_block_ratio(refs["post_block"], flines) or 0.0    # ~ corrigido
    ev = f"sim_pos={sp:.2f} sim_pre={sv:.2f}"
    if max(sv, sp) < 0.55:
        return "INDETERMINADO", round(max(sv, sp), 3), ev + " (refs fracas)"
    if abs(sp - sv) < 0.03:
        return "INDETERMINADO", round(sp - sv, 3), ev + " (empate)"
    return ("CORRIGIDO" if sp > sv else "VULNERAVEL"), round(sp - sv, 3), ev


def fork_pre_file(fork, path, before_iso):
    j = R.api(f"https://api.github.com/repos/{fork}/commits",
              params={"path": path, "until": before_iso, "per_page": 1})
    if j and isinstance(j, list) and j:
        return R.get_file(fork, path, j[0]["sha"])
    return None


# --- auditar o worklist ---
with open(WL, encoding="utf-8-sig", newline="") as f:
    wl = list(csv.DictReader(f))

head_adoption = OrderedDict()   # (fork, cve) -> (veredito, score, ev)
n_audit = 0
for row in wl:
    up, cve = row["upstream"], row["cve"]
    refs = refs_for(up, cve)
    if not refs:
        row["veredito_humano"] = ""
        row["observacao"] = "auto: referência indisponível"
        continue
    if row["origem"] == "upstream_pre":
        code = R.get_file(up, refs["fp"], refs["parent"])
        fork = up
        _, score, ev = adoption(code, refs)                 # só como sanity check
        verd = "VULNERAVEL"                                 # vulnerável POR CONSTRUÇÃO
        ev = "pré-fix (def. vulneravel); sanity " + ev
    else:
        fork = row["instancia"].split()[0]
        code = fork_pre_file(fork, refs["fp"], refs["fix_date"])
        verd, score, ev = adoption(code, refs)
    row["veredito_humano"] = verd if verd in ("CORRIGIDO", "VULNERAVEL") else ""
    row["observacao"] = f"auto(bloco-2B) score={score} [{ev}]"
    n_audit += 1
    # adoção no HEAD (resposta direta: o fork adotou depois?)
    if row["origem"] == "fork_pre":
        hv, hs, hev = adoption(R.get_file(fork, refs["fp"]), refs)
        head_adoption[(fork, cve)] = (hv, hs, hev)

# regravar worklist com veredito automático + evidência
cols = list(wl[0].keys())
for extra in ("veredito_ia",):
    if extra not in cols:
        cols.append(extra)
for row in wl:
    row["veredito_ia"] = row.get("veredito_humano", "")
with open(WL, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(wl)

# tabela de adoção no HEAD
head_path = os.path.join(HERE, "resultados_2026-07-09", "auditoria_adocao_HEAD.csv")
with open(head_path, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.writer(f); w.writerow(["fork", "cve", "adotou_no_HEAD", "score", "evidencia"])
    for (fork, cve), (v, s, ev) in head_adoption.items():
        w.writerow([fork, cve, v, s, ev])

# resumo
from collections import Counter
vc = Counter(r["veredito_humano"] or "INDET" for r in wl)
hc = Counter(v for v, _, _ in head_adoption.values())
print(f"Instâncias auditadas no worklist: {n_audit}/{len(wl)}")
print(f"  veredito dos NEGATIVOS: {dict(vc)}")
print(f"    -> VULNERAVEL confirma negativo válido; CORRIGIDO = rótulo ruim (fork já tinha o fix)")
print(f"\nAdoção no HEAD (forks x CVE, n={len(head_adoption)}): {dict(hc)}")
adotaram = [f"{k[0]} / {k[1]}" for k, v in head_adoption.items() if v[0] == "CORRIGIDO"]
nao = [f"{k[0]} / {k[1]}" for k, v in head_adoption.items() if v[0] == "VULNERAVEL"]
print(f"  ADOTARAM no HEAD ({len(adotaram)}):")
for a in adotaram:
    print(f"    ✓ {a}")
print(f"  NÃO adotaram / ainda expostos ({len(nao)}):")
for a in nao:
    print(f"    ✗ {a}")
print(f"\n-> worklist preenchido: {WL}")
print(f"-> adoção HEAD: {head_path}")
