# -*- coding: utf-8 -*-
"""
rw6 — Paixao et al. (2026), "Automated Detection of Configuration-Specific
      Security Vulnerabilities via Patch Analysis" (PatchLens, PACMSE/FSE 2026,
      DOI 10.1145/3808126).

O QUE **NAO** E REPRODUZIDO (e por que)
  PatchLens calcula a Vulnerability Impact Condition (VIC): um predicado booleano
  sobre opcoes de compilacao que caracteriza quais VARIANTES de um sistema
  altamente configuravel (C/C++) continham a falha. Isso depende de (i) codigo
  nao-preprocessado com diretivas #ifdef/#if e (ii) analise do build system
  (Kbuild/Make/Autotools) para a condicao de presenca do ARQUIVO.
  O ecossistema Matrix e Python/Rust/Kotlin/Swift/TypeScript/Go: nao ha
  variabilidade em tempo de compilacao, nao ha condicoes de presenca e nao ha
  espaco de variantes. Reproduzir VIC aqui seria inventar dado — nao se faz.

O QUE E REPRODUZIDO (o mecanismo transferivel)
  O nucleo tecnico do PatchLens antes das condicoes de presenca:
  **mapear cada hunk do diff para a subarvore da AST que o contem** e raciocinar
  no escopo dessa subarvore, em vez de raciocinar sobre o arquivo inteiro
  (Sec. 3.2 do artigo: "maps each hunk to its corresponding AST nodes by
  comparing these two trees" + agregacao dos hunks por DISJUNCAO).

  Aqui esse mecanismo e aplicado ao problema da dissertacao (fork corrigido ou
  nao), trocando o escopo da comparacao da Camada 2:

      Camada 2 atual  : sim_AST(arquivo_do_fork, arquivo_pos_patch)
      rw6 (PatchLens) : sim_AST(declaracao_do_fork, declaracao_pos_patch)
                        onde "declaracao" = menor no de funcao/metodo/classe que
                        CONTEM o hunk do patch, localizado como no PatchLens

  A agregacao entre hunks/declaracoes segue a disjuncao do artigo (basta um
  hunk casar) — que e a mesma regra da uniao ja usada pela dissertacao.

POR QUE ISSO IMPORTA AQUI
  O diagnostico do run 2026-08-17 mostrou 7 falsos positivos, 5 deles causados
  por arquivo-monolito: `src/client.ts` tem ~1e5 tokens, o patch tem 4 linhas, e
  a similaridade de arquivo inteiro chega a 0,987 mesmo com o fork NAO tendo a
  correcao. Escopo de hunk e exatamente o remedio que o PatchLens sugere.

ENTRADA  : <run>/dissertation_resultados.json + <run>/evidencias_dissertacao/
           (todo o codigo ja esta em disco — nao usa rede nem token)
SAIDA    : resultados_AAAA-MM-DD/rw6_patchlens_hunk.json

Uso:
    python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py
    python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py --run resultados_2026-08-18
"""
import argparse
import difflib
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from _common import dump_dated, STATUS_PRIORITY  # noqa: E402
import pipeline_core  # noqa: E402
from pipeline_core import (  # noqa: E402
    _init_parsers, _norm, compute_sim, classify, classify_dual, MARGIN_ZI,
)

# Nos que contam como "declaracao" (o alvo do mapeamento hunk -> subarvore).
# Equivalente funcional do "hunk's root node" do PatchLens, sem as condicoes de
# presenca (que nao existem nestas linguagens).
DECL_TYPES = {
    "python":     {"function_definition", "class_definition"},
    "rust":       {"function_item", "impl_item", "struct_item", "enum_item", "trait_item"},
    "kotlin":     {"function_declaration", "class_declaration", "object_declaration"},
    "swift":      {"function_declaration", "class_declaration", "protocol_declaration"},
    "typescript": {"function_declaration", "method_definition", "class_declaration",
                   "method_signature", "public_field_definition", "lexical_declaration"},
    "tsx":        {"function_declaration", "method_definition", "class_declaration",
                   "method_signature", "public_field_definition", "lexical_declaration"},
    "go":         {"function_declaration", "method_declaration", "type_declaration"},
}
EXT_LANG = {".py": "python", ".rs": "rust", ".kt": "kotlin", ".swift": "swift",
            ".ts": "typescript", ".tsx": "tsx", ".go": "go"}


def ts_parse(src, lang):
    _init_parsers()
    # NAO importar _PARSERS por valor: _init_parsers() REATRIBUI o global do
    # modulo, entao uma referencia importada continuaria apontando p/ dict vazio.
    parsers = pipeline_core._PARSERS
    if lang not in parsers:
        return None
    TSParser, language = parsers[lang]
    return TSParser(language).parse(bytes(src, "utf-8")).root_node


def hunk_lines(pre, post):
    """Linhas (1-based) de `post` tocadas pelo patch — equivalente aos hunks do diff."""
    a, b = pre.splitlines(), post.splitlines()
    linhas = set()
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag == "equal":
            continue
        for j in range(j1, max(j2, j1 + 1)):
            linhas.add(j + 1)
    return linhas


def nome_do_no(node, src_bytes):
    f = node.child_by_field_name("name")
    if f is not None:
        return src_bytes[f.start_byte:f.end_byte].decode("utf-8", "replace")
    for c in node.children:
        if c.type in ("identifier", "simple_identifier", "type_identifier",
                      "property_identifier", "field_identifier"):
            return src_bytes[c.start_byte:c.end_byte].decode("utf-8", "replace")
    return None


def coletar_decls(root, src, lang):
    """
    UMA passada na arvore, devolvendo todas as declaracoes com sua faixa de
    linhas: [(ini, fim, tipo, nome, no)]. Uma passada so importa: em arquivo
    -monolito (src/client.ts, ~10k linhas) refazer o caminhamento por linha de
    hunk custava minutos por comparacao.
    """
    b = bytes(src, "utf-8")
    tipos = DECL_TYPES.get(lang, set())
    out, pilha = [], [root]
    while pilha:
        n = pilha.pop()
        if n.type in tipos:
            nome = nome_do_no(n, b)
            if nome:
                out.append((n.start_point[0] + 1, n.end_point[0] + 1,
                            n.type, nome, n))
        pilha.extend(n.children)
    return out


def indexar(decls):
    """{(tipo, nome): no} — a menor declaracao vence em caso de nome repetido."""
    idx = {}
    for ini, fim, tipo, nome, no in sorted(decls, key=lambda d: d[1] - d[0]):
        idx.setdefault((tipo, nome), no)
    return idx


def decl_do_hunk(decls, linhas):
    """
    Menor declaracao que CONTEM cada hunk (o "hunk's root node" do PatchLens).
    Retorna [(tipo, nome, no)] sem repeticao.
    """
    achados, vistos = [], set()
    for ln in sorted(linhas):
        melhor = None
        for ini, fim, tipo, nome, no in decls:
            if ini <= ln <= fim and (melhor is None or (fim - ini) < (melhor[1] - melhor[0])):
                melhor = (ini, fim, tipo, nome, no)
        if melhor is not None:
            chave = (melhor[2], melhor[3])
            if chave not in vistos:
                vistos.add(chave)
                achados.append((melhor[2], melhor[3], melhor[4]))
    return achados


_CACHE_UPSTREAM = {}


def preparar_upstream(chave, pre, post, lang):
    """
    Hunks + declaracoes do upstream para um (cve, arquivo). Fica em cache porque
    e identico para os 3 forks do mesmo upstream — recalcular o diff de um
    arquivo-monolito por fork triplicava o custo.
    """
    if chave in _CACHE_UPSTREAM:
        return _CACHE_UPSTREAM[chave]
    r_post = ts_parse(post, lang)
    r_pre = ts_parse(pre, lang)
    if r_post is None:
        v = (None, None, None, "linguagem sem parser")
    else:
        linhas = hunk_lines(pre, post)
        if not linhas:
            v = (None, None, None, "diff vazio entre pre e pos")
        else:
            alvos = decl_do_hunk(coletar_decls(r_post, post, lang), linhas)
            if not alvos:
                v = (None, None, None,
                     "hunk fora de qualquer declaracao (topo do arquivo)")
            else:
                decls_pre = (indexar(coletar_decls(r_pre, pre, lang))
                             if r_pre is not None else {})
                v = (alvos, decls_pre, len(linhas), "")
    _CACHE_UPSTREAM[chave] = v
    return v


def avaliar(chave, pre, post, fork_src, lang):
    """
    Devolve (label_2a, label_2b, sim_patch, sim_vuln, n_hunks, n_localizados,
             motivo) no escopo do hunk, agregando hunks por DISJUNCAO.
    """
    alvos, decls_pre, _n_linhas, motivo_up = preparar_upstream(chave, pre, post, lang)
    if motivo_up:
        return None, None, None, None, 0, 0, motivo_up

    r_fork = ts_parse(fork_src, lang)
    if r_fork is None:
        return None, None, None, None, len(alvos), 0, "linguagem sem parser"
    decls_fork = indexar(coletar_decls(r_fork, fork_src, lang))

    melhor = ("", "", -1.0, -1.0)
    n_loc = 0
    for tipo, nome, no_post in alvos:
        no_fork = decls_fork.get((tipo, nome))
        if no_fork is None:
            continue                      # declaracao ausente no fork
        n_loc += 1
        a_post = _norm(no_post)
        a_fork = _norm(no_fork)
        if a_post is None or a_fork is None:
            continue
        sim_patch = compute_sim(a_post, a_fork)[2]

        no_pre = decls_pre.get((tipo, nome))
        a_pre = _norm(no_pre) if no_pre is not None else None
        sim_vuln = compute_sim(a_pre, a_fork)[2] if a_pre is not None else None

        l2a = classify(sim_patch)
        # classify_dual devolve (label, delta) — guardar so o label, senao a
        # comparacao com strings mais adiante nunca casa.
        l2b = (classify_dual(sim_patch, sim_vuln, MARGIN_ZI)[0]
               if sim_vuln is not None else None)
        # disjuncao entre hunks: fica o veredito de maior prioridade
        if STATUS_PRIORITY.get(l2a, 0) > STATUS_PRIORITY.get(melhor[0], 0) or \
                sim_patch > melhor[2]:
            melhor = (l2a, l2b, sim_patch, sim_vuln)

    if n_loc == 0:
        return None, None, None, None, len(alvos), 0, \
            "declaracao do patch ausente no fork"
    return melhor[0], melhor[1], melhor[2], melhor[3], len(alvos), n_loc, ""


def caminho_evidencia(base, cve, prefixo, filepath, fork=None):
    d = os.path.join(base, cve.replace("/", "_"))
    plano = filepath.replace("/", "_")
    if fork:
        owner, repo = fork.split("/")
        nome = "fork_%s_%s_%s" % (owner, repo, plano)
    else:
        nome = "%s_%s" % (prefixo, plano)
    p = os.path.join(d, nome)
    return p if os.path.exists(p) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="resultados_2026-08-17",
                    help="pasta datada com dissertation_resultados.json e evidencias")
    ap.add_argument("--refazer-metricas", action="store_true",
                    help="recalcula as metricas a partir do JSON ja gravado, sem "
                         "refazer o trabalho de AST (~30s por comparacao)")
    args = ap.parse_args()

    proj = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    run_dir = args.run if os.path.isabs(args.run) else os.path.join(proj, args.run)
    ev = os.path.join(run_dir, "evidencias_dissertacao")
    rows = json.load(open(os.path.join(run_dir, "dissertation_resultados.json"),
                          encoding="utf-8"))

    gt_path = os.path.join(run_dir, "gt_dissertation_resultados.json")
    gt = {}
    if os.path.exists(gt_path):
        for g in json.load(open(gt_path, encoding="utf-8")):
            if g["gt_label"] in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
                gt[(g["fork"], g["cve"])] = g["gt_label"]

    detalhes = []
    por_par_hunk, por_par_arq = defaultdict(str), defaultdict(str)
    motivos = defaultdict(int)

    if args.refazer_metricas:
        antigo = json.load(open(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "resultados_" + os.getenv("RW_DATE", ""), "rw6_patchlens_hunk.json"),
            encoding="utf-8")) if os.getenv("RW_DATE") else None
        if antigo is None:
            from _common import OUTDIR
            antigo = json.load(open(os.path.join(OUTDIR, "rw6_patchlens_hunk.json"),
                                    encoding="utf-8"))
        detalhes = antigo["detalhes"]
        motivos = defaultdict(int, antigo.get("motivos_de_nao_localizacao", {}))
        for x in detalhes:
            par = (x["fork"], x["cve"])
            for campo, alvo in (("veredito_hunk", por_par_hunk),
                                ("veredito_arquivo", por_par_arq)):
                if STATUS_PRIORITY.get(x[campo], 0) > STATUS_PRIORITY.get(alvo[par], 0):
                    alvo[par] = x[campo]
        rows = []

    for r in rows:
        if r["status"] == "FILE_NOT_FOUND":
            continue
        cve, fp, fork = r["cve_id"], r["filepath"], r["fork"]
        lang = EXT_LANG.get(os.path.splitext(fp)[1].lower(), r["language"])
        p_pre = caminho_evidencia(ev, cve, "upstream_pre", fp)
        p_post = caminho_evidencia(ev, cve, "upstream_post", fp)
        p_fork = caminho_evidencia(ev, cve, None, fp, fork)
        par = (fork, cve)

        # escopo de ARQUIVO (pipeline atual), para comparacao lado a lado
        if STATUS_PRIORITY.get(r["status"], 0) > STATUS_PRIORITY.get(por_par_arq[par], 0):
            por_par_arq[par] = r["status"]

        if not (p_pre and p_post and p_fork):
            motivos["evidencia ausente em disco"] += 1
            continue

        pre = open(p_pre, encoding="utf-8", errors="replace").read()
        post = open(p_post, encoding="utf-8", errors="replace").read()
        forksrc = open(p_fork, encoding="utf-8", errors="replace").read()

        print("  [%d/%d] %s %s %s" % (len(detalhes) + 1, len(rows), fork, cve,
                                        os.path.basename(fp)), flush=True)
        l2a, l2b, sp, sv, n_h, n_loc, motivo = avaliar(
            (cve, fp), pre, post, forksrc, lang)
        if motivo:
            motivos[motivo] += 1

        # veredito do escopo de hunk: exige que a declaracao exista no fork.
        # Se o patch alterou uma declaracao que o fork nem tem, a evidencia nao
        # sustenta "corrigido" -> zona de incerteza (nunca falsa seguranca).
        if l2a is None:
            veredito = "ZONA_INCERTEZA"
        elif l2a == "CORRIGIDO" and l2b in (None, "CORRIGIDO", "ZONA_INCERTEZA"):
            veredito = "CORRIGIDO" if l2b != "VULNERAVEL" else "ZONA_INCERTEZA"
        elif l2a == "CORRIGIDO":
            veredito = "ZONA_INCERTEZA"
        else:
            veredito = l2a

        if STATUS_PRIORITY.get(veredito, 0) > STATUS_PRIORITY.get(por_par_hunk[par], 0):
            por_par_hunk[par] = veredito

        detalhes.append({
            "fork": fork, "cve": cve, "arquivo": fp, "lang": lang,
            "hunks": n_h, "declaracoes_localizadas_no_fork": n_loc,
            "sim_hunk_pos": None if sp is None else round(sp, 4),
            "sim_hunk_pre": None if sv is None else round(sv, 4),
            "label_2a_hunk": l2a, "label_2b_hunk": l2b,
            "veredito_hunk": veredito,
            "sim_arquivo_pos": r.get("sim_2a"), "veredito_arquivo": r["status"],
            "motivo": motivo,
        })

    def metricas(por_par):
        tp = fp_ = fn = tn = 0
        for par, lbl in gt.items():
            auto = por_par.get(par, "")
            pos_auto, pos_gt = auto == "CORRIGIDO", lbl == "CONFIRMED_PATCHED"
            if pos_auto and pos_gt:
                tp += 1
            elif pos_auto:
                fp_ += 1
            elif pos_gt:
                fn += 1
            else:
                tn += 1
        prec = tp / (tp + fp_) if tp + fp_ else None
        rec = tp / (tp + fn) if tp + fn else None
        f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
        return {"TP": tp, "FP": fp_, "FN": fn, "TN": tn,
                "precision": None if prec is None else round(prec, 4),
                "recall": None if rec is None else round(rec, 4),
                "f1": None if f1 is None else round(f1, 4)}

    # Variante: escopo de hunk + "Regra A" (o 2A so vale como CORRIGIDO se o
    # fork estiver ao menos tao proximo do pos-patch quanto do pre-patch).
    # Os 3 FPs que sobrevivem ao escopo de hunk sao todos delta < 0.
    por_par_regraA = defaultdict(str)
    for x in detalhes:
        v = x["veredito_hunk"]
        sp, sv = x["sim_hunk_pos"], x["sim_hunk_pre"]
        if v == "CORRIGIDO" and sp is not None and sv is not None and (sp - sv) < 0:
            v = "ZONA_INCERTEZA"
        par = (x["fork"], x["cve"])
        if STATUS_PRIORITY.get(v, 0) > STATUS_PRIORITY.get(por_par_regraA[par], 0):
            por_par_regraA[par] = v

    m_arq, m_hunk = metricas(por_par_arq), metricas(por_par_hunk)
    m_regraA = metricas(por_par_regraA)
    fps_corrigidos = sorted(
        "%s :: %s" % p for p, l in gt.items()
        if l == "CONFIRMED_VULNERABLE" and por_par_arq.get(p) == "CORRIGIDO"
        and por_par_hunk.get(p) != "CORRIGIDO")
    novos_fn = sorted(
        "%s :: %s" % p for p, l in gt.items()
        if l == "CONFIRMED_PATCHED" and por_par_arq.get(p) == "CORRIGIDO"
        and por_par_hunk.get(p) != "CORRIGIDO")

    out = {
        "trabalho": "Paixao et al. (2026) — PatchLens (PACMSE/FSE, DOI 10.1145/3808126)",
        "run_analisado": args.run,
        "reproduzido": "mapeamento hunk -> subarvore da AST; comparacao no escopo "
                       "da declaracao que contem o patch; hunks unidos por disjuncao",
        "nao_reproduzido": "Vulnerability Impact Condition (VIC): exige C/C++ "
                           "nao-preprocessado com #ifdef e analise de build system; "
                           "nao ha variabilidade de compilacao no ecossistema Matrix",
        "n_linhas_analisadas": len(detalhes),
        "n_pares_fork_cve": len(por_par_hunk),
        "gt_conclusivos": len(gt),
        "metricas_escopo_arquivo (pipeline atual)": m_arq,
        "metricas_escopo_hunk (PatchLens)": m_hunk,
        "metricas_escopo_hunk + regra A (delta>=0)": m_regraA,
        "falsos_positivos_corrigidos_pelo_escopo_de_hunk": fps_corrigidos,
        "verdadeiros_positivos_perdidos": novos_fn,
        "motivos_de_nao_localizacao": dict(motivos),
        "detalhes": detalhes,
    }
    p = dump_dated("rw6_patchlens_hunk.json", out)

    print("=== rw6 PatchLens / Paixao et al. 2026 (escopo de hunk) ===")
    print("Run analisado            : %s" % args.run)
    print("Linhas (fork x CVE x arq): %d" % len(detalhes))
    print("Pares com GT conclusivo  : %d" % len(gt))
    print()
    print("%-28s %4s %3s %4s %3s  %-6s %-6s %-6s" %
          ("escopo", "TP", "FP", "FN", "TN", "P", "R", "F1"))
    for nome, m in (("arquivo (pipeline atual)", m_arq), ("hunk (PatchLens)", m_hunk),
                    ("hunk + regra A (delta>=0)", m_regraA)):
        print("%-28s %4d %3d %4d %3d  %-6s %-6s %-6s" %
              (nome, m["TP"], m["FP"], m["FN"], m["TN"],
               m["precision"], m["recall"], m["f1"]))
    print()
    print("FPs eliminados pelo escopo de hunk : %d" % len(fps_corrigidos))
    for x in fps_corrigidos:
        print("   %s" % x)
    print("TPs perdidos pelo escopo de hunk   : %d" % len(novos_fn))
    for x in novos_fn[:10]:
        print("   %s" % x)
    if motivos:
        print("\nMotivos de nao-localizacao do hunk:")
        for k, v in sorted(motivos.items(), key=lambda x: -x[1]):
            print("   %-50s %d" % (k, v))
    print("\n-> %s" % p)


if __name__ == "__main__":
    main()
