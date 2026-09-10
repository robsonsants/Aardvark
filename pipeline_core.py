"""
pipeline_core.py  -  Shared module: AST parsing, similarity and classification
==========================================================================
Structural core of the verification pipeline, reused by every layer.
Imported by:
  - pipeline_dissertation.py  (Layer 2A single reference + Layer 2B dual reference)
  - ground_truth.py           (automated ground truth from patch key lines)

Exported functions:
  parse_code(src, lang)            -> normalised ASTNode
  patch_subtree(before, after)     -> subtree of the nodes introduced by the patch
  levenshtein(a, b)                -> edit distance over lists
  zss_dist(a, b)                   -> Zhang-Shasha tree edit distance (ASTNode)
  compute_sim(ref, tgt)            -> (sim_lev, sim_zss, sim_combined, method)
  compute_sim_seqs(seq_r, seq_t)   -> same, taking ready-made in-order sequences
  classify(score)                  -> CORRIGIDO | NAO_CORRIGIDO | ZONA_INCERTEZA
  classify_dual(sim_patch, sim_vuln, margin) -> Layer 2B label from the delta
  inorder(ast_node)                -> in-order list (alias of ASTNode.inorder)

Exported constants:
  ZSS_NODE_LIMIT    int   -- node limit for using Zhang-Shasha (600)
  THRESHOLD_HIGH    float -- upper threshold for CORRIGIDO / patched (0.80)
  THRESHOLD_LOW     float -- lower threshold for NAO_CORRIGIDO / not patched (0.35)
  MARGIN_ZI         float -- default uncertainty-zone margin for Layer 2B (0.05)

Supported languages: python, rust, kotlin, swift, typescript, tsx, go.

Performance note (changed since the July snapshot): levenshtein() delegates to
rapidfuzz (C++, bit-parallel Myers) when the package is installed. The distance is
exactly the same (unit costs 1/1/1); the pure-Python O(n x m) loop is kept as a
fallback. On monolithic files (e.g. src/client.ts of matrix-js-sdk, ~1e5 tokens)
that loop took ~40 min per comparison and made the wider Phase 2 unfeasible.

Verdict labels are kept in Portuguese because they are literal values stored in
every versioned result file; see the glossary in README.md.
"""

import sys
import time

# Windows: o console usa cp1252 e quebra ao imprimir caracteres como '→'/'✓'.
# Como este módulo é importado por todos os scripts de análise, forçar UTF-8
# aqui cobre o pipeline inteiro (idempotente e inofensivo em Linux/macOS).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ─── Parsers (carregados lazy) ────────────────────────────────────────────────
_PARSERS: dict = {}
_ZSS_OK        = None

ZSS_NODE_LIMIT = 600    # acima disso usa só Levenshtein (evita MemoryError)
THRESHOLD_HIGH = 0.80   # sim >= THRESHOLD_HIGH → CORRIGIDO
THRESHOLD_LOW  = 0.35   # sim <= THRESHOLD_LOW  → NAO_CORRIGIDO
MARGIN_ZI      = 0.05   # |delta| <= MARGIN_ZI  → ZONA_INCERTEZA (Camada 2B)


def _init_parsers() -> None:
    """Carrega os parsers Tree-sitter na primeira chamada (startup rápido)."""
    global _PARSERS
    if _PARSERS:
        return
    print("  [core] Carregando parsers AST... ", end="", flush=True)
    t0 = time.perf_counter()
    from tree_sitter import Language, Parser as TSParser
    import tree_sitter_kotlin as tsk
    import tree_sitter_python as tsp
    import tree_sitter_swift  as tssw
    import tree_sitter_rust   as tsr
    _PARSERS = {
        "kotlin": (TSParser, Language(tsk.language())),
        "python": (TSParser, Language(tsp.language())),
        "swift":  (TSParser, Language(tssw.language())),
        "rust":   (TSParser, Language(tsr.language())),
    }
    # Parsers adicionais para as categorias client/integration (TypeScript) e
    # bridge (Go) do ecossistema Matrix. Carregados de forma tolerante: se o
    # pacote não estiver instalado, a linguagem apenas fica indisponível
    # (parse_code retorna None) em vez de derrubar todo o pipeline.
    try:
        import tree_sitter_typescript as tsts
        _PARSERS["typescript"] = (TSParser, Language(tsts.language_typescript()))
        _PARSERS["tsx"]        = (TSParser, Language(tsts.language_tsx()))
    except Exception as e:  # noqa: BLE001
        print(f"[TS indisponível: {e}] ", end="")
    try:
        import tree_sitter_go as tsgo
        _PARSERS["go"] = (TSParser, Language(tsgo.language()))
    except Exception as e:  # noqa: BLE001
        print(f"[Go indisponível: {e}] ", end="")
    print(f"OK ({time.perf_counter()-t0:.1f}s)")


def _init_zss() -> None:
    """Verifica se a biblioteca zss está disponível."""
    global _ZSS_OK
    if _ZSS_OK is not None:
        return
    try:
        from zss import simple_distance  # noqa: F401
        _ZSS_OK = True
    except ImportError:
        _ZSS_OK = False


# ─── Normalização de nós AST ─────────────────────────────────────────────────
# Tipos ignorados (comentários e anotações)
_IGN = frozenset({
    "comment", "line_comment", "block_comment",
    "multiline_comment", "doc_comment",
})
# Identificadores → VAR
_VARS = frozenset({
    "identifier", "simple_identifier", "value_identifier",
    "field_identifier", "type_identifier", "name_identifier",
    # TypeScript: nomes de propriedade e formas abreviadas de objeto
    "property_identifier", "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
    # Go: nome de pacote (ex.: `fmt` em fmt.Println)
    "package_identifier",
})
# Literais de string → STR
# (template_string do TS é deixado sem colapsar de propósito: contém
#  substituições ${...} com código que deve permanecer visível na AST)
_STRS = frozenset({
    "string_literal", "string", "interpreted_string_literal",
    "raw_string_literal", "string_content", "string_fragment",
})
# Literais numéricos → NUM
_NUMS = frozenset({
    "integer_literal", "float_literal", "number_literal",
    "decimal_integer_literal", "hex_literal",
    # TypeScript: todos os literais numéricos usam o tipo "number"
    "number",
    # Go: literais inteiros, imaginários e de runa
    "int_literal", "imaginary_literal", "rune_literal",
})
# Estruturas de laço → LOOP
_LOOPS = frozenset({
    "for_statement", "for_expression", "for_in_expression",
    "while_statement", "while_expression", "loop_expression",
    # TypeScript: for...of / for...in
    "for_in_statement",
})


# ─── Nó de AST normalizado ───────────────────────────────────────────────────
class ASTNode:
    """Nó de AST normalizado com serialização in-order e suporte a ZSS."""
    __slots__ = ("label", "children")

    def __init__(self, label: str, children=None):
        self.label    = label
        self.children = children or []

    def size(self) -> int:
        return 1 + sum(c.size() for c in self.children)

    def inorder(self) -> list:
        """Serialização in-order: filho-esquerdo → raiz → filhos-direitos."""
        out = []
        mid = len(self.children) // 2
        for c in self.children[:mid]:
            out.extend(c.inorder())
        out.append(self.label)
        for c in self.children[mid:]:
            out.extend(c.inorder())
        return out

    def to_zss(self):
        from zss import Node as ZN
        n = ZN(self.label)
        for c in self.children:
            n.addkid(c.to_zss())
        return n


def inorder(node: ASTNode) -> list:
    """Alias funcional de ASTNode.inorder() — compatibilidade com camada2b."""
    return node.inorder()


# ─── Normalização recursiva da árvore Tree-sitter ────────────────────────────
def _norm(node) -> ASTNode | None:
    """Converte um nó Tree-sitter em ASTNode normalizado. Retorna None se ignorado."""
    if node.type in _IGN:
        return None
    lbl = node.type
    if   node.type in _VARS:  lbl = "VAR"
    elif node.type in _STRS:  lbl = "STR"
    elif node.type in _NUMS:  lbl = "NUM"
    elif node.type in _LOOPS: lbl = "LOOP"
    children = [x for x in (_norm(c) for c in node.children) if x is not None]
    return ASTNode(lbl, children)


# ─── Parsing ─────────────────────────────────────────────────────────────────
def parse_code(src: str, lang: str) -> ASTNode | None:
    """
    Parseia código-fonte e retorna ASTNode normalizado.

    Args:
        src:  código-fonte como string
        lang: linguagem ('kotlin', 'rust', 'swift', 'python')

    Returns:
        ASTNode normalizado, ou None se a linguagem não for suportada.
    """
    _init_parsers()
    if lang not in _PARSERS:
        return None
    TSParser, language = _PARSERS[lang]
    tree = TSParser(language).parse(bytes(src, "utf-8"))
    return _norm(tree.root_node)


# Alias para compatibilidade com camada2b_experimento.py
def parse_tree(src: str, lang: str) -> ASTNode | None:
    """Alias de parse_code — compatibilidade com camada2b_experimento.py."""
    return parse_code(src, lang)


# Alias para compatibilidade com camada2b_experimento.py
def normalize_ast(node: ASTNode) -> ASTNode:
    """Identidade — a normalização já ocorre em parse_code/_norm."""
    return node


# ─── Subárvore do patch ───────────────────────────────────────────────────────
def patch_subtree(before: ASTNode, after: ASTNode) -> ASTNode:
    """
    Extrai a subárvore de nós presentes em 'after' mas ausentes em 'before'.
    Representa a adição estrutural introduzida pelo patch.
    """
    new = set(after.inorder()) - set(before.inorder())

    def keep(n: ASTNode) -> ASTNode | None:
        if n.label in new:
            return n
        ch = [x for x in (keep(c) for c in n.children) if x is not None]
        return ASTNode(n.label, ch) if ch else None

    return keep(after) or after


# ─── Distâncias ──────────────────────────────────────────────────────────────
try:
    from rapidfuzz.distance import Levenshtein as _RF_LEV
except ImportError:            # ambiente sem rapidfuzz → cai no laço puro
    _RF_LEV = None


def levenshtein(a: list, b: list) -> int:
    """
    Distância de Levenshtein sobre listas de tokens (serialização in-order).

    Usa rapidfuzz (C++, bit-paralelo de Myers) quando disponível: o resultado é
    a MESMA distância de edição (custos 1/1/1), só que ~10³× mais rápido. O laço
    O(n × m) em Python puro fica como fallback — em arquivos grandes (ex.:
    src/client.ts do matrix-js-sdk, ~10⁵ tokens) ele levava ~40 min por
    comparação, o que inviabilizava a Fase 2 no ecossistema ampliado.
    """
    if _RF_LEV is not None:
        return int(_RF_LEV.distance(a, b))

    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[:], i
        for j in range(1, n + 1):
            dp[j] = (prev[j - 1] if a[i - 1] == b[j - 1]
                     else 1 + min(prev[j], dp[j - 1], prev[j - 1]))
    return dp[n]


def zss_dist(a: ASTNode, b: ASTNode) -> int | None:
    """
    Distância Zhang-Shasha entre duas árvores.
    Retorna None se: biblioteca zss ausente, ou qualquer árvore excede
    ZSS_NODE_LIMIT nós (restrição de memória O(n²)).
    """
    _init_zss()
    if not _ZSS_OK:
        return None
    if a.size() > ZSS_NODE_LIMIT or b.size() > ZSS_NODE_LIMIT:
        return None
    try:
        from zss import simple_distance
        return int(simple_distance(a.to_zss(), b.to_zss()))
    except MemoryError:
        return None


# ─── Similaridade combinada ───────────────────────────────────────────────────
def compute_sim(ref: ASTNode, tgt: ASTNode) -> tuple:
    """
    Calcula similaridade combinada entre dois ASTNodes.

    Fluxo:
      1. Serializa ambos em in-order
      2. Calcula distância de Levenshtein → sim_lev
      3. Tenta Zhang-Shasha se ambas as árvores ≤ ZSS_NODE_LIMIT nós → sim_zss
      4. Se ZSS disponível: sim_combined = 0.45×lev + 0.55×zss
         Senão:             sim_combined = sim_lev  (method='lev_only')

    Returns:
        (sim_lev, sim_zss_or_None, sim_combined, method_str)
    """
    seq_r, seq_t = ref.inorder(), tgt.inorder()
    return compute_sim_seqs(seq_r, seq_t, ref, tgt)


def compute_sim_seqs(seq_r: list, seq_t: list,
                     ref: ASTNode = None,
                     tgt: ASTNode = None) -> tuple:
    """
    Versão de compute_sim que aceita sequências in-order já calculadas.
    Usada por camada2b_experimento.py que pré-serializa as ASTs.

    Se ref e tgt (ASTNodes) forem fornecidos, tenta ZSS adicionalmente.
    """
    d_lev = levenshtein(seq_r, seq_t)
    s_lev = max(0.0, 1.0 - d_lev / max(len(seq_r), len(seq_t), 1))

    if ref is not None and tgt is not None:
        d_zss = zss_dist(ref, tgt)
    else:
        d_zss = None

    if d_zss is not None:
        s_zss  = max(0.0, 1.0 - d_zss / max(ref.size(), tgt.size(), 1))
        s_comb = 0.45 * s_lev + 0.55 * s_zss
        method = "lev+zss"
    else:
        s_zss  = None
        s_comb = s_lev
        method = "lev_only"

    return s_lev, s_zss, s_comb, method


# ─── Classificação ────────────────────────────────────────────────────────────
def classify(score: float) -> str:
    """
    Classifica um score de similaridade em três estados (Camada 2A).

    Thresholds empíricos:
      score >= 0.80  → CORRIGIDO
      score <= 0.35  → NAO_CORRIGIDO
      contrário      → ZONA_INCERTEZA
    """
    if score >= THRESHOLD_HIGH:
        return "CORRIGIDO"
    if score <= THRESHOLD_LOW:
        return "NAO_CORRIGIDO"
    return "ZONA_INCERTEZA"


def classify_dual(sim_patch: float, sim_vuln: float,
                  margin: float = MARGIN_ZI) -> tuple:
    """
    Classificação por referência dupla (Camada 2B), inspirada em PDiff/BinXray.

    Compara a proximidade do fork com o pós-patch (sim_patch) e com o
    pré-patch (sim_vuln). A decisão é tomada pelo delta:

      delta = sim_patch - sim_vuln
      delta > +margin  → CORRIGIDO   (mais próximo do pós-patch)
      delta < -margin  → VULNERAVEL  (mais próximo do pré-patch)
      |delta| ≤ margin → ZONA_INCERTEZA

    Returns:
        (label: str, delta: float)
    """
    delta = sim_patch - sim_vuln
    if delta > margin:
        return "CORRIGIDO", delta
    if delta < -margin:
        return "VULNERAVEL", delta
    return "ZONA_INCERTEZA", delta


# ─── Auto-teste rápido ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("pipeline_core.py — teste de importação")
    print(f"  ZSS_NODE_LIMIT : {ZSS_NODE_LIMIT}")
    print(f"  THRESHOLD_HIGH : {THRESHOLD_HIGH}")
    print(f"  THRESHOLD_LOW  : {THRESHOLD_LOW}")
    print(f"  MARGIN_ZI      : {MARGIN_ZI}")

    # Teste básico de Levenshtein
    a = ["A", "B", "C", "D"]
    b = ["A", "B", "X", "D"]
    d = levenshtein(a, b)
    assert d == 1, f"Levenshtein esperado 1, obtido {d}"
    print(f"\n  levenshtein(['A','B','C','D'], ['A','B','X','D']) = {d}  ✓")

    # Teste de classify
    assert classify(0.95) == "CORRIGIDO"
    assert classify(0.55) == "ZONA_INCERTEZA"
    assert classify(0.20) == "NAO_CORRIGIDO"
    print("  classify(0.95/0.55/0.20) = CORRIGIDO/ZONA_INCERTEZA/NAO_CORRIGIDO  ✓")

    # Teste de classify_dual
    label, delta = classify_dual(0.90, 0.70)
    assert label == "CORRIGIDO", f"Esperado CORRIGIDO, obtido {label}"
    label, delta = classify_dual(0.70, 0.90)
    assert label == "VULNERAVEL"
    label, delta = classify_dual(0.80, 0.78)
    assert label == "ZONA_INCERTEZA"
    print("  classify_dual: CORRIGIDO/VULNERAVEL/ZONA_INCERTEZA  ✓")

    print("\n  Todos os testes passaram. Parsers AST não testados (requerem tree-sitter).")