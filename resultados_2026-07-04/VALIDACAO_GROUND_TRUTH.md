# Ground-truth validation — human audit + anchored ground truth (GT v2)

> ## ⚠ Dated document — July 2026 run
>
> This validation belongs to `resultados_2026-07-04/`, which was produced by the pipeline
> that silently discarded the test-file evidence and therefore **underestimates the method**
> (see `CHANGELOG.md` §1). Its ground truth also contains **no natural negatives**, which is
> why every pair here is conclusive-and-patched.
>
> The current ground truth, with 33 positives and 7 negatives plus an independent human
> audit, is described in [`../RESULTS_2026-08-31.md`](../RESULTS_2026-08-31.md) §2.

> Summarises the human audit and the automatic re-verification anchored on the line
> that **actually fixes** the vulnerability (rather than on imports).
> Artefacts: `gt_v2_resultados.json`, `gt_v2_metricas.json`, `auditoria_manual_gt.*`.
> Regenerate offline with `python gt_v2_anchors.py --check` (no network, no token).

## 1. Why the ground truth needed a v2

The original `ground_truth.py` (GT v1) measured the presence of the **first 15 lines
added** by the fix commit. The manual audit made it evident — and the human reviewer
flagged it independently — that many of those lines are **non-corrective**: `import`s,
docstrings, generic enum variants. That contaminates the ground truth's confidence:

- **CVE-2025-61672 (synapse):** the "missing" lines were only `import`s
  (`from typing…`, `_pydantic_compat`). The fork does carry the fix, just with a
  different import style. GT v1 → AMBIGUOUS (false uncertainty).
- **CVE-2025-66622 (rust-sdk):** the ground truth matched on `JoinRule::Invite/Knock/
  Private`, which appear in any Matrix codebase. The line that actually fixes the issue
  (`match c.join_rule()` + `warn!("Encountered a custom join rule")`) was never tested.
  **The human reviewer was misled by this**: they confirmed one fork and disagreed on
  two identical ones (#38 vs #39/#40).
- **CVE-2023-38700 (irc):** the ground truth matched on field declarations
  (`processingInvitesForRooms`), which are unchanged context. The real fix is
  ``cacheKey = `${roomId}-${eventId}` ``.

**Conclusion:** the ground-truth metric must be anchored on the line that genuinely fixes.

## 2. GT v2 — one corrective anchor per CVE

For each CVE we extracted, from the real upstream diff, the line or token that exists
only if the fix is present. Verification is done **offline** against the already
downloaded files (`evidencias_gt_dissertacao/`). Rule: PATCHED when the anchor is
present (union across the CVE's fix commits).

| CVE | Corrective anchor (never an import) |
|-----|-------------------------------------|
| CVE-2022-39252 | `should_accept_forward` (rejects a key forward from an unverified user/device) |
| CVE-2023-38690 | `public assertConnected(): Client` |
| CVE-2023-38700 | ``cacheKey = `${roomId}-${eventId}` `` (per-room cache; prevents cross-room) |
| CVE-2023-43656 | `shouldInterruptAfterDeadline`/QuickJS — **moved** to `src/generic/WebhookTransformer.ts` |
| CVE-2024-26131 | `fun Intent.isValid()` + `className in allowList` |
| CVE-2024-26132 | `File(context.filesDir, "media")` |
| CVE-2024-31208 | `visited_chains` (graph traversal; replaces `get_links_from` O(n²)) |
| CVE-2024-34353 | `setup_and_resume()` after `regenerate_olm` |
| CVE-2024-39691 | `memberJoinTs.set` without `origin_server_ts` (uses `Date.now()`) |
| CVE-2024-52505 | hardened channel regex `^#([^:\x00-\x1F\s,]){1,199}$` |
| CVE-2025-23197 | `if (install.suspended_at)` |
| CVE-2025-27146 | `sanitized_topic` (sanitises newlines in the IRC TOPIC) |
| CVE-2025-27606 | `ignoreLogoutServerError = true` |
| CVE-2025-48937 | `Some(i) if i != sender` (sender_data user_id ≠ event sender) |
| CVE-2025-61672 | `validate_json_object(body, self.KeyUploadRequestBody)` |
| CVE-2025-66622 | `warn!("Encountered a custom join rule")` |

## 3. Result — GT v1 vs GT v2

| | GT v1 (raw patch lines) | GT v2 (corrective line) |
|---|:---:|:---:|
| Conclusive pairs | 34 / 43 | **43 / 43** |
| Ambiguous | 9 | **0** |
| PATCHED / VULNERABLE | 34 / 0 | 43 / 0 |
| TP · FP · FN · TN | 23·0·11·0 | 26·0·17·0 |
| Precision | 1.000 | **1.000** |
| Recall | 0.676 | 0.605 |
| F1 | 0.807 | 0.754 |
| Kappa | 0.0 | 0.0 |

**The 9 ambiguous cases of GT v1 were an artefact of matching imports.** Anchored on the
corrective line, all of them resolve to PATCHED:
- 3× CVE-2025-61672 (synapse) → PATCHED (anchor `validate_json_object` present); the
  automatic verdict was CORRIGIDO, so they become TP.
- 3× CVE-2025-66622 (rust-sdk) → PATCHED (anchor `warn custom join rule` present); the
  automatic verdict was ZONA_INCERTEZA, so they become FN.
- 3× CVE-2023-43656 (hookshot) → PATCHED **cross-file** (fix migrated to
  `WebhookTransformer.ts`); automatic verdict ZONA_INCERTEZA, so they become FN.

## 4. Findings that support the methodology

1. **The 11 original false negatives are correct ground truth** (confirmed both by the
   human audit and by the anchors): those forks do carry the real fix; the AST layer was
   merely conservative and left them in the uncertainty zone. So the FNs are a limitation
   of the structural method, not of the ground truth. That is exactly the gap the
   embeddings fill (union AST ∪ embeddings reaches recall 1.0).

2. **Kappa = 0 is a real property of the population, not a measurement artefact.**
   Checked on the corrective line, **none** of the 43 pairs is vulnerable: **active**
   divergent forks (`ahead_by > 0`, recent activity) do track upstream security fixes.
   With no negative class, Kappa collapses by construction. **Real precision can therefore
   only be measured on CONSTRUCTED negatives** (upstream at pre-fix + pre-adoption
   versions) — which is what `run_precision_eval.py` does.

3. **Confirmed and characterised limitation: single-path HEAD verification fails when the
   upstream restructures the fix.** Two modes were observed:
   - *Repository migration* (element-web → monorepo): the file disappears from the path
     → FILE_NOT_FOUND.
   - *Intra-repository move* (hookshot CVE-2023-43656): the fix moves out of
     `GenericHook.ts` into `WebhookTransformer.ts`. Anchoring on the old file yields a
     **false VULNERABLE**; only a cross-file search (performed manually) recovers the
     correct PATCHED verdict.
   → This motivates the next step: **project-level ranked similarity search**, not bound
     to a fixed path.

4. **A ground truth built on imports and generic lines misleads even the human auditor**
   (CVE-2025-66622, #38 vs #39/#40). Anchoring on the corrective line is a validity
   requirement for the ground truth — a methodological recommendation of this work.

## 5. Reviewer's manual verdicts × GT v2

- **#1–#34 (CONFIRMS the ground truth):** 100% agreement with GT v2 (11 FN + 23 TP, all
  PATCHED).
- **#35–#37 (CVE-2023-43656, "CONFIRMS" the ambiguous label):** GT v2 shows these are in
  fact PATCHED (the fix moved file) — a reclassification, not a reviewer error.
- **#38 CONFIRMS / #39–#40 DISAGREES (CVE-2025-66622):** all three are PATCHED. The
  reviewer's divergence was induced by the generic lines shown to them; GT v2 fixes it.
- **#41–#43 (CVE-2025-61672, CONFIRMS):** PATCHED (the absences were imports).

## 6. Reproducibility note

`gt_v2_anchors.py` rebuilds this ground truth offline from the anchors above and the
files in `evidencias_gt_dissertacao/`, and `--check` verifies it against the published
labels. **40 of the 43 labels follow directly from files in this repository.** The
remaining 3 (CVE-2023-43656) rest on the manual cross-file inspection described in
section 4.3, because only the pre-migration file was archived as evidence; run
`gt_v2_anchors.py --no-manual` to see the unaided automated result (40 PATCHED,
3 VULNERABLE).

## 7. Final numbers

- **Ground truth (GT v2, anchored):** 43/43 conclusive fork×CVE pairs, **43 PATCHED,
  0 VULNERABLE**. The human audit and the corrective-line check agree.
- **RQ1 (reliability) — structural (AST) matching against GT v2:**
  Precision **1.000** (zero false positives), Recall **0.605**, F1 **0.754**.
  Complementarity with embeddings raises recall to 1.0.
- **Real precision:** must be measured on constructed negatives, since the population of
  active forks contains no natural negatives.
