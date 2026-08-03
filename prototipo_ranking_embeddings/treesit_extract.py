# -*- coding: utf-8 -*-
"""Robust function/method extraction via tree-sitter, reusing the parsers already
configured in pipeline_core.py (python/rust/kotlin/swift/typescript/tsx/go).

Replaces the prototype's regex-based extraction, which was fragile with multi-line
signatures, keyword-less methods in TypeScript, and similar cases. Returns [] when the
language parser is unavailable, so the caller can apply its own fallback.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_core as pc

FUNC_TYPES = {
    "python": {"function_definition"},
    "rust": {"function_item"},
    "kotlin": {"function_declaration"},
    "swift": {"function_declaration"},
    "typescript": {"function_declaration", "method_definition",
                   "generator_function_declaration", "method_signature"},
    "tsx": {"function_declaration", "method_definition",
            "generator_function_declaration", "method_signature"},
    "go": {"function_declaration", "method_declaration"},
}
_NAME_TYPES = {"identifier", "property_identifier", "simple_identifier",
               "field_identifier", "type_identifier"}


def _parser(lang):
    try:
        pc._init_parsers()
    except Exception:
        return None
    p = getattr(pc, "_PARSERS", {})
    return p.get(lang)


def _name_of(node, sb):
    n = node.child_by_field_name("name")
    if n is not None:
        return sb[n.start_byte:n.end_byte].decode("utf-8", "replace")
    for c in node.children:
        if c.type in _NAME_TYPES:
            return sb[c.start_byte:c.end_byte].decode("utf-8", "replace")
    return None


def functions(src, lang):
    ent = _parser(lang)
    if not ent or not src:
        return []
    TSParser, language = ent
    try:
        tree = TSParser(language).parse(bytes(src, "utf-8"))
    except Exception:
        return []
    sb = bytes(src, "utf-8")
    types = FUNC_TYPES.get(lang, set())
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in types:
            out.append({
                "name": _name_of(node, sb),
                "start": node.start_point[0], "end": node.end_point[0],
                "text": sb[node.start_byte:node.end_byte].decode("utf-8", "replace"),
            })
        stack.extend(node.children)
    return out


def enclosing_function(src, lang, line0):
    cands = [f for f in functions(src, lang) if f["start"] <= line0 <= f["end"]]
    if not cands:
        return None
    return min(cands, key=lambda f: f["end"] - f["start"])   # o mais interno


def function_by_name(src, lang, name):
    fns = [f for f in functions(src, lang) if f["name"] == name]
    if not fns:
        return None
    return max(fns, key=lambda f: f["end"] - f["start"])      # a maior (corpo real)


if __name__ == "__main__":
    demo = {
        "python": "class A:\n    async def on_POST(\n        self, r\n    ) -> int:\n        return validate(r)\n",
        "rust": "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
    }
    for lang, code in demo.items():
        fns = functions(code, lang)
        print(lang, "->", [(f["name"], f["start"], f["end"]) for f in fns])
