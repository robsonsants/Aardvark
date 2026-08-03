# -*- coding: utf-8 -*-
"""
rw2 — Cheng et al. (2025), "VERCATION: Precise Vulnerable OSS Version Identification
      based on Static Analysis and LLM" (IEEE TSE).  [trabalho MAIS similar]

REPRODUCED METHOD
  Structural similarity over a normalised Abstract Syntax Tree (AST), measured by tree
  edit distance (Zhang-Shasha). SINGLE reference: the fork file's normalised AST is
  compared against the POST-fix file; if similarity >= threshold (0.80) the fork counts
  as patched. This is Layer 2A of our pipeline and the declared starting point of the
  approach.

SIGNAL USED: label_2a / sim_2a (per fork x CVE pair, union over files).
GOAL: show the FALSE-NEGATIVE REDUCTION relative to the literal hash (rw1).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import load_rows, agg_by_key, load_gt_pairs, dump_dated

agg = agg_by_key(load_rows())
gt, _ = load_gt_pairs()

detected = sorted(k for k, v in agg.items() if v["ast_label"] == "CORRIGIDO")
gt_keys = list(gt.keys())
tp = sum(1 for k in gt_keys if agg.get(k, {}).get("ast_label") == "CORRIGIDO")
fn = len(gt_keys) - tp
# recuperados frente ao hash: pares GT que o hash perdeu mas a AST detecta
rec_over_hash = sorted(k for k in gt_keys
                       if agg[k]["ast_label"] == "CORRIGIDO" and not agg[k]["hash_patched"])

out = {
    "trabalho": "Cheng et al. (2025) — VERCATION (AST normalizada + edit distance)",
    "papel_na_proposta": "Camada 2A / similaridade estrutural (ponto de partida, §4.4)",
    "metodo": "fork CORRIGIDO sse sim_AST(fork, pos_patch) >= 0.80 (referência única)",
    "n_pares_fork_cve": len(agg),
    "n_detectados_corrigidos": len(detected),
    "gt_conclusivos": len(gt_keys),
    "TP": tp, "FN": fn,
    "recall": round(tp / len(gt_keys), 4) if gt_keys else None,
    "recuperados_frente_ao_hash": rec_over_hash,
    "n_recuperados_frente_ao_hash": len(rec_over_hash),
    "detectados": detected,
}
p = dump_dated("rw2_vercation2025_ast.json", out)
print("=== rw2 VERCATION / Cheng et al. 2025 (AST 1 referência) ===")
print(f"Pares fork×CVE analisados : {out['n_pares_fork_cve']}")
print(f"Detectados como CORRIGIDO : {out['n_detectados_corrigidos']}")
print(f"GT conclusivos (patched)  : {out['gt_conclusivos']}")
print(f"TP / FN                   : {tp} / {fn}   (recall={out['recall']})")
print(f"Recuperados vs hash (rw1) : {len(rec_over_hash)}")
print(f"-> {p}")
