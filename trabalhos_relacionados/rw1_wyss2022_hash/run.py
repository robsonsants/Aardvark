# -*- coding: utf-8 -*-
"""
rw1 — Wyss et al. (2022), "What the Fork? Finding Hidden Code Clones in npm" (ICSE).

REPRODUCED METHOD
  Clone detection by WHOLE-FILE HASH. A fork counts as patched for a CVE only if the
  cryptographic hash of the patched file in the fork is identical to the hash of the
  post-fix file upstream. It never inspects the inside of the file (closed box). This
  is the "literal verification" of Layer 1 -- the baseline that motivates moving to
  AST-based comparison.

SIGNAL USED: sha_match (per fork x CVE pair, union over files).
EVALUATION: over the pairs with a conclusive ground truth (all of them genuinely
  patched), how many this technique DETECTS (TP) and how many it MISSES (FN).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import load_rows, agg_by_key, load_gt_pairs, dump_dated

agg = agg_by_key(load_rows())
gt, _ = load_gt_pairs()

detected = sorted(k for k, v in agg.items() if v["hash_patched"])
gt_keys = list(gt.keys())
tp = sum(1 for k in gt_keys if agg.get(k, {}).get("hash_patched"))
fn = len(gt_keys) - tp

out = {
    "trabalho": "Wyss et al. (2022) — What the Fork? (hash de arquivo inteiro)",
    "papel_na_proposta": "Camada 1 / verificação literal (linha de base)",
    "metodo": "fork CORRIGIDO sse sha256(arquivo_fork) == sha256(arquivo_pos_patch_upstream)",
    "n_pares_fork_cve": len(agg),
    "n_detectados_corrigidos": len(detected),
    "gt_conclusivos": len(gt_keys),
    "TP": tp, "FN": fn,
    "recall": round(tp / len(gt_keys), 4) if gt_keys else None,
    "detectados": detected,
}
p = dump_dated("rw1_wyss2022_hash.json", out)
print("=== rw1 Wyss et al. 2022 (hash literal) ===")
print(f"Pares fork×CVE analisados : {out['n_pares_fork_cve']}")
print(f"Detectados como CORRIGIDO : {out['n_detectados_corrigidos']}")
print(f"GT conclusivos (patched)  : {out['gt_conclusivos']}")
print(f"TP / FN                   : {tp} / {fn}   (recall={out['recall']})")
print(f"-> {p}")
