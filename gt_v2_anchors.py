# -*- coding: utf-8 -*-
"""
gt_v2_anchors.py  —  Ground truth v2: verification anchored on the corrective line
===================================================================================
Rebuilds ground truth v2 OFFLINE from the evidence files already downloaded into
resultados_2026-07-04/evidencias_gt_dissertacao/. No network access and no token.

Why a v2 at all. Ground truth v1 (ground_truth.py) scored the presence of the first
lines ADDED by the fix commit. Many of those lines are non-corrective -- imports,
docstrings, generic enum variants -- so a fork carrying the real fix could still be
labelled AMBIGUOUS, and a fork missing it could match on context. The manual audit
showed this misled even the human reviewer.

What v2 does instead. For each CVE we define ONE anchor: the line or token that exists
only if the security fix is present. A (fork, CVE) pair is PATCHED when the anchor
appears in any of that CVE's evidence files for the fork (union across fix commits).

Pairs resolved by Layer 1 (identical file hash) need no anchor: an identical file
trivially contains the fix, and no evidence file was downloaded for them.

Usage:
    python gt_v2_anchors.py [--dir resultados_2026-07-04] [--check]

    --check  compare the recomputed labels against the published gt_v2_resultados.json
             and exit non-zero on any divergence.

Outputs (same schema as the published artefacts):
    <dir>/gt_v2_resultados.json   -- per-pair label, GT v1 label and automatic verdict
    <dir>/gt_v2_metricas.json     -- Precision/Recall/F1/Accuracy/Kappa + anchor table
"""
import argparse
import io
import json
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------- anchor table
# One anchor per CVE: a token that only exists once the fix is applied. Kept as a
# regex so whitespace and formatting differences between forks do not matter.
# The human-readable rationale is what gets written into gt_v2_metricas.json.
ANCHORS = {
    "CVE-2022-39252": (
        r"should_accept_forward",
        "should_accept_forward (rejects a key forward from an unverified user/device)"),
    "CVE-2023-38690": (
        r"assertConnected",
        "public assertConnected(): Client (corrected visibility)"),
    "CVE-2023-38700": (
        r"cacheKey\s*=|\$\{roomId\}-\$\{eventId\}",
        "cacheKey = `${roomId}-${eventId}` (per-room event cache, prevents cross-room)"),
    "CVE-2023-43656": (
        r"shouldInterruptAfterDeadline|quickjs|QuickJS",
        "shouldInterruptAfterDeadline / QuickJS timeout -- MOVED to "
        "src/generic/WebhookTransformer.ts (verified cross-file)"),
    "CVE-2024-26131": (
        r"isValid\(\)|allowList|allowlist",
        "fun Intent.isValid() + className in allowList (Intent allowlist)"),
    "CVE-2024-26132": (
        r"filesDir\s*,\s*[\"']media[\"']",
        'File(context.filesDir, "media") (writes to an isolated subdirectory)'),
    "CVE-2024-31208": (
        r"visited_chains",
        "visited_chains (pruned graph traversal, replaces get_links_from O(n^2))"),
    "CVE-2024-34353": (
        r"setup_and_resume",
        "setup_and_resume() after regenerate_olm (resynchronises the backup key)"),
    "CVE-2024-39691": (
        r"memberJoinTs\.set",
        "memberJoinTs.set without origin_server_ts (uses Date.now(), blocks ts spoofing)"),
    "CVE-2024-52505": (
        r"\^#\(\[\^|1,199",
        'hardened channel regex "^#([^:\\x00-\\x1f\\s,]){1,199}$"'),
    "CVE-2025-23197": (
        r"suspended_at",
        "if (install.suspended_at) -- skips suspended installations"),
    "CVE-2025-27146": (
        r"sanitized_topic",
        "sanitized_topic (sanitises newlines in the IRC TOPIC)"),
    "CVE-2025-27606": (
        r"ignoreLogoutServerError",
        "ignoreLogoutServerError = true in restartApp"),
    "CVE-2025-48937": (
        r"if\s+i\s*!=\s*sender|Some\(i\)\s*if",
        "Some(i) if i != sender (rejects when sender_data user_id != event sender)"),
    "CVE-2025-61672": (
        r"validate_json_object",
        "validate_json_object(body, self.KeyUploadRequestBody) (strict Pydantic validation)"),
    "CVE-2025-66622": (
        r"Encountered a custom join rule",
        'warn!("Encountered a custom join rule") (rejects custom join rules)'),
}


# ------------------------------------------------- manually resolved cross-file case
# CVE-2023-43656 (hookshot) is the documented file-restructuring finding: between the
# fix commit and the fork's HEAD the fix MIGRATED out of src/Connections/GenericHook.ts
# into src/generic/WebhookTransformer.ts. The evidence downloaded for this CVE is the
# OLD path only, so the anchor is legitimately absent there and the automated check
# below reports VULNERABLE. The published label is PATCHED, established by a MANUAL
# cross-file inspection of the forks (shouldInterruptAfterDeadline x2, QuickJS x5,
# vm2 = 0) recorded in VALIDACAO_GROUND_TRUTH.md section 4.3.
#
# We keep that manual resolution explicit rather than silently baking it into the
# anchor: these are the only 3 of the 43 labels that do not follow from a file in this
# repository. Run with --no-manual to see the unaided automated result.
CROSS_FILE_MANUAL = {
    "CVE-2023-43656": "fix moved to src/generic/WebhookTransformer.ts; "
                      "verified manually cross-file (see VALIDACAO_GROUND_TRUTH.md)",
}


def fork_slug(fork):
    """Evidence files are named <fork-owner>_<repo>_<sha8>_<flattened path>."""
    return fork.split("/")[0]


def anchor_present(text, pattern):
    return re.search(pattern, text, re.IGNORECASE) is not None


def evidence_files(evid_dir, cve, fork):
    """Every downloaded file for this (CVE, fork), across the CVE's fix commits."""
    d = os.path.join(evid_dir, cve)
    if not os.path.isdir(d):
        return []
    slug = fork_slug(fork).lower()
    return [os.path.join(d, f) for f in os.listdir(d)
            if f.lower().startswith(slug + "_")]


def label_pair(evid_dir, cve, fork, is_sha, use_manual=True):
    """PATCHED / VULNERABLE / NO_EVIDENCE for one (fork, CVE) pair."""
    if is_sha:
        # Layer 1 matched the file hash exactly: the fork file IS the patched file.
        return "PATCHED", "sha_match"
    if cve not in ANCHORS:
        return "NO_EVIDENCE", "no anchor defined"
    pattern = ANCHORS[cve][0]
    files = evidence_files(evid_dir, cve, fork)
    if not files:
        return "NO_EVIDENCE", "no evidence file downloaded"
    # Union across fix commits: present in ANY evidence file is enough.
    for path in files:
        try:
            txt = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if anchor_present(txt, pattern):
            return "PATCHED", os.path.basename(path)
    if use_manual and cve in CROSS_FILE_MANUAL:
        return "PATCHED", "MANUAL: " + CROSS_FILE_MANUAL[cve]
    return "VULNERABLE", f"anchor absent in {len(files)} file(s)"


def kappa(tp, fp, fn, tn):
    n = tp + fp + fn + tn
    if not n:
        return 0.0
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
    return 0.0 if pe == 1 else round((po - pe) / (1 - pe), 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="resultados_2026-07-04")
    ap.add_argument("--check", action="store_true",
                    help="compare against the published gt_v2_resultados.json")
    ap.add_argument("--no-manual", action="store_true",
                    help="ignore the manually resolved cross-file case (CVE-2023-43656), "
                         "showing what the anchors alone establish from this repository; "
                         "implies --check so the published artefacts are never overwritten "
                         "with this reduced labelling")
    args = ap.parse_args()
    # --no-manual is a diagnostic view, not a ground truth: never let it write.
    if args.no_manual:
        args.check = True

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.dir)
    evid = os.path.join(base, "evidencias_gt_dissertacao")
    published = json.load(open(os.path.join(base, "gt_v2_resultados.json"),
                               encoding="utf-8"))

    rows, disagree = [], []
    for p in published:
        lbl, why = label_pair(evid, p["cve"], p["fork"], p.get("is_sha", False),
                              use_manual=not args.no_manual)
        rows.append({"upstream": p["upstream"], "category": p["category"],
                     "cve": p["cve"], "fork": p["fork"], "gt_v1": p["gt_v1"],
                     "gt_v2": lbl, "auto": p["auto"], "is_sha": p.get("is_sha", False),
                     "evidence": why})
        if lbl != p["gt_v2"]:
            disagree.append((p["cve"], p["fork"], p["gt_v2"], lbl, why))

    # Confusion matrix of the automatic AST verdict against this ground truth.
    tp = sum(1 for r in rows if r["gt_v2"] == "PATCHED" and r["auto"] == "CORRIGIDO")
    fn = sum(1 for r in rows if r["gt_v2"] == "PATCHED" and r["auto"] != "CORRIGIDO")
    fp = sum(1 for r in rows if r["gt_v2"] == "VULNERABLE" and r["auto"] == "CORRIGIDO")
    tn = sum(1 for r in rows if r["gt_v2"] == "VULNERABLE" and r["auto"] != "CORRIGIDO")
    prec = round(tp / (tp + fp), 4) if tp + fp else 0.0
    rec = round(tp / (tp + fn), 4) if tp + fn else 0.0
    f1 = round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0

    print("=" * 74)
    print("Ground truth v2 -- rebuilt offline from the corrective anchors")
    print("=" * 74)
    print(f"pairs                : {len(rows)}")
    for lbl in ("PATCHED", "VULNERABLE", "NO_EVIDENCE"):
        print(f"  {lbl:<12}       : {sum(1 for r in rows if r['gt_v2'] == lbl)}")
    print(f"  of which sha_match : {sum(1 for r in rows if r['is_sha'])}")
    n_manual = sum(1 for r in rows if str(r["evidence"]).startswith("MANUAL:"))
    print(f"  of which MANUAL    : {n_manual}  (cross-file, see VALIDACAO_GROUND_TRUTH.md)")
    print(f"TP/FP/FN/TN          : {tp}/{fp}/{fn}/{tn}")
    print(f"Precision            : {prec}")
    print(f"Recall               : {rec}")
    print(f"F1                   : {f1}")
    print(f"Kappa                : {kappa(tp, fp, fn, tn)}")

    if args.check:
        print()
        if disagree:
            print(f"DIVERGENCES against the published labels: {len(disagree)}")
            for cve, fork, pub, got, why in disagree:
                print(f"  {cve} {fork}: published={pub} recomputed={got} ({why})")
            sys.exit(1)
        print("OK -- every recomputed label matches the published gt_v2_resultados.json")
        return

    json.dump(rows, open(os.path.join(base, "gt_v2_resultados.json"), "w",
                         encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"method": "GT v2 (anchored on the corrective line)",
               "n_pairs": len(rows),
               "PATCHED": sum(1 for r in rows if r["gt_v2"] == "PATCHED"),
               "VULNERABLE": sum(1 for r in rows if r["gt_v2"] == "VULNERABLE"),
               "TP": tp, "FP": fp, "FN": fn, "TN": tn,
               "precision": prec, "recall": rec, "f1": f1,
               "kappa": kappa(tp, fp, fn, tn),
               "anchors_per_cve": {k: v[1] for k, v in ANCHORS.items()}},
              open(os.path.join(base, "gt_v2_metricas.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"\n-> {base}")


if __name__ == "__main__":
    main()
