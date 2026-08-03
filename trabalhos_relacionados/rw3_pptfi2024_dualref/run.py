# -*- coding: utf-8 -*-
"""
rw3 — He et al. (2024), "PPTFI: Patch Presence Test for Function-Irrelevant Patches"
      (MSN);  e Xu et al. (2023), "PatchDiscovery" (IEEE TSE).

REPRODUCED METHOD
  Patch Presence Test (PPT) with DUAL REFERENCE. The target (fork) is compared both
  against the signature of the VULNERABLE version (pre-patch) AND against the PATCHED
  version (post-patch); the verdict follows whichever reference is closer:
      delta = sim(fork, post_patch) - sim(fork, pre_patch)
      delta >  +margin  -> CORRIGIDO      (patched)
      delta <  -margin  -> VULNERAVEL     (vulnerable)
      |delta| <= margin -> ZONA_INCERTEZA (uncertainty -> escalate to human audit)
  This is Layer 2B. It resolves the cases where the single reference (rw2) fails on
  code-REMOVAL patches (false positives), preserving precision.

SINAL USADO: label_2b / delta (por par fork×CVE, união sobre arquivos).
"""
import sys, os
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import load_rows, agg_by_key, load_gt_pairs, dump_dated

agg = agg_by_key(load_rows())
gt, _ = load_gt_pairs()

dist = Counter(v["dualref_label"] or "SEM_2B" for v in agg.values())
detected = sorted(k for k, v in agg.items() if v["dualref_label"] == "CORRIGIDO")
gt_keys = list(gt.keys())
tp = sum(1 for k in gt_keys if agg.get(k, {}).get("dualref_label") == "CORRIGIDO")
# na 2B, o que não é CORRIGIDO conclui em ZONA_INCERTEZA (nunca falso "seguro")
uncertain = sum(1 for k in gt_keys if agg.get(k, {}).get("dualref_label") == "ZONA_INCERTEZA")
fn = len(gt_keys) - tp

out = {
    "trabalho": "He et al. (2024) PPTFI / Xu et al. (2023) PatchDiscovery — PPT dupla referência",
    "papel_na_proposta": "Camada 2B / referência dupla (discriminador de incerteza)",
    "metodo": "delta = sim(fork,pos) - sim(fork,pre); |delta|<=0.05 -> ZONA_INCERTEZA",
    "distribuicao_vereditos": dict(dist),
    "n_pares_fork_cve": len(agg),
    "n_detectados_corrigidos": len(detected),
    "gt_conclusivos": len(gt_keys),
    "TP": tp, "FN_como_zona_incerteza": uncertain, "FN_total": fn,
    "recall": round(tp / len(gt_keys), 4) if gt_keys else None,
    "detectados": detected,
}
p = dump_dated("rw3_pptfi2024_dualref.json", out)
print("=== rw3 PPTFI/PatchDiscovery (PPT dupla referência) ===")
print(f"Distribuição vereditos    : {dict(dist)}")
print(f"Detectados como CORRIGIDO : {out['n_detectados_corrigidos']}")
print(f"GT conclusivos (patched)  : {out['gt_conclusivos']}")
print(f"TP / FN(=zona incerteza)  : {tp} / {fn}   (recall={out['recall']})")
print(f"-> {p}")
