# Peer-review feedback: what it said, what the data now answers, what we will change

An earlier version of this study was submitted to a conference and **rejected**. Three
independent reports came back. This document exists because the criticism was good: it is
recorded here in full, matched against what the corrected run can now answer, and turned
into an ordered list of changes.

The reports are paraphrased rather than quoted — the substance is what matters, and the
substance is not in dispute. **All three were right.** None of them misread the paper.

---

## 1. The one criticism all three reports converged on

> Recall was measured on a population where **every pair was positive**, and precision on
> a **constructed** negative set — and the paper never compared the method against a
> classifier that simply answers "patched" every time.

This is the criticism that mattered, and it is the one that is now **settled by data
rather than by argument**. The current run (`resultados_2026-08-31_v2`) has a single real
population containing **7 natural negatives** in 40 conclusive pairs. There is no
constructed set any more, and no second ground truth used interchangeably with the first.

It also uncovered something the reviewers could not have known: the reason there were
never any negatives to find was partly a **defect in our own pipeline**, which discarded
the test-file evidence in every earlier run (`CHANGELOG.md` §1). Fixing it moved Kappa from
−0.024 to 0.590 on the same population.

---

## 2. Every criticism, grouped, with its current status

**PR** = raised and already resolved · **P** = raised, valid, action listed below ·
**PP** = partly valid

### A. Evaluation population and metrics

| Criticism | | Status |
|---|---|---|
| Two different populations evaluated and never signposted | **PR** | One real population now, with natural negatives. The constructed 44P/56N set is abandoned |
| Recall measured where every pair is patched | **PR** | 33 positives, 7 real negatives |
| No constant-classifier baseline in the main table | **P** | **Measured** (E1). It is uncomfortable: the union beats it by +0.019 in F1. What separates them is Kappa (0.590 vs 0.000) and false positives (2 vs 7). Both go in the main table |
| Two ground truths used interchangeably | **PR** | Automated GT **plus** human audit, agreement measured (87.8%), always reported side by side, never mixed |
| Behaviour close to a single-class classifier | **P** | **Quantified** (E1, E6). True in F1, false in Kappa and in false-positive count |
| No confidence intervals, no significance testing | **P** | **Added** (E4). And the answer is unwelcome: at n=40 nothing is significant, including the difference from the trivial classifier |

### B. How the thresholds were obtained

| Criticism | | Status |
|---|---|---|
| No holdout or k-fold to derive the parameters ("cardinal sin") | **P** | **Done** (E2). Good news: not overfitted — out-of-sample F1 0.941 vs 0.923. Bad news: **not identifiable** — all five folds select `thr_high = 0.60` under the automated oracle, four of five select `0.90` under the human one |
| Thresholds presented in the method chapter as if they were given | **P** | Structural. They must be presented as a **policy choice**, with the sensitivity sweep and the operating curve, not as a derivation |
| Without a way to separate small from large patches, the results cannot be trusted | **P** | **Tested** (E3), and the answer is better than "we cannot": patch size is *not* a usable discriminant (it drags 18 cases and halves recall), while the **sign of the delta** resolves the same failures by moving 2 |

### C. Failure analysis and dataset

| Criticism | | Status |
|---|---|---|
| No analysis of where the method fails | **P** | **Done** (E5): all five errors, one by one, with evidence and diagnosis |
| Pairs excluded for lack of "bilateral file existence"; the CVE set looks hand-picked | **PP** | `FILE_NOT_FOUND` is now a first-class result (10 of 51), not a footnote. But the underlying point stands: **the corpus is what survived, not a sample**, and it must be described that way |
| Ground truth annotated by a single reviewer | **P** | **Still true. The largest open gap in the work** — see §4, item 1 |
| Adoption lag: how is it measured, and why only part of the pairs? | **PR** | `dataset_temporal.py` documents it: median 268 days, n=53 measurable, 31 rows flagged unreliable with the reason recorded |

### D. Claims that were simply inaccurate

| Criticism | | Status |
|---|---|---|
| **Layer 1 is not SHA-256; it is a string comparison** | **P** | **Confirmed in the code.** `layer1_sha()` evaluates `upstream_post == fork_content`. Nothing is hashed. See §4, item 4 |
| The "semantic" layer is not semantic | **P** | Correct, and worse than the reviewer could see: the embedding layer **has not run since July 2026**. See §4, item 5 |
| "The uncertainty zone is absent from existing approaches" overstates novelty | **P** | Classification **with a reject option** is classical. The claim goes; the mechanism stays |
| Inconsistent attribution of the dual-reference principle | **P** | A real inconsistency between two passages. Fixed in the text |

### E. Related work

| Criticism | | Status |
|---|---|---|
| FIBER (USENIX Security 2018) is missing | **P** | Correct and important — it is *the* patch-presence-testing reference, and later work positions itself against it. Must be cited |
| VUDDY, Movery, V1scan missing | **P** | Correct. **Movery** matters most: vulnerable code **modified after reuse** is the nearest neighbour of our uncertainty zone. To be cited, declaring that they target C/C++ and are therefore not direct baselines |
| Several citations do not support the sentences they are attached to | **P** | Editorial and true; each one to be checked against the source |

### F. Presentation

| Criticism | | Status |
|---|---|---|
| Undefined symbols, poorly formatted tables, the pipeline figure shows no flow | **P** | Editorial, all valid |
| Method and experimental setup interleaved | **P** | Structural: setup separated from method, thresholds after their derivation |
| Vocabulary drifts (`NOT PATCHED`/`VULNERABLE`, `UNCERTAINTY ZONE`/`AMBIGUOUS`) | **P** | One vocabulary, defined once — see §4, item 6 |

---

## 3. The change of framing (the most important item)

The rejected version was written to claim:

> *"our pipeline detects patch propagation better than the alternatives."*

**The data does not support that sentence** — not the data in the paper, and not the data
now: at n=40 nothing is statistically distinguishable (E4), and the union beats the best
single layer by exactly one pair.

The data does support, with room to spare, a different thesis:

> **How much of the propagation of security fixes into divergent forks is automatically
> verifiable — and what stops the rest.**

Under that framing, what currently reads as weakness becomes result:

| Reads today as a weakness | Becomes |
|---|---|
| Only 7 of 24 candidate repositories were verifiable | **Result:** data availability is the first ceiling |
| 10 of 51 verifications end in `FILE_NOT_FOUND` | **Result:** reach into the fork is the second ceiling |
| 60 of 63 comparisons fall back to Levenshtein rather than tree edit distance | **Result:** the third ceiling belongs to the instrument, and it is measured |
| All the difficulty sits in one upstream | **Result:** most of the ecosystem is trivially verifiable; the hard problem is a small, identifiable minority |
| 31 of 51 pairs are inheritance, not propagation | **Result:** the coverage metric used in this literature measures the wrong thing |
| Nothing is significant at n=40 | **Declared threat**, with intervals instead of assertions |

This is not repackaging. It is the reading the reports themselves endorsed when they
praised the macroscopic findings (the adoption lag, the concentration of coverage, the
CVE-2023-43656 case) — findings about **limits** were what they recognised as strong.

---

## 4. The improvements we will make, in order

### 1. A second reviewer on the 13 `matrix-rust-sdk` pairs — *highest value per hour*

**Why these 13 and not all 41:** that upstream contains **6 of the 7 negatives and 5 of the
5 errors**. Inter-rater agreement measured exactly where the decisions are hard is worth
more than agreement measured where every method scores perfectly.

This is the only criticism from the three reports that remains **entirely** open. Cost:
about two hours of a second person's time, using the worklist
`auditoria_manual.py` already produces. Everything else on this list is our own writing
time.

### 2. Report metrics on the hard subset as well as the whole

Four of the five upstreams give P=1.000 and R=1.000 **with any threshold**. Reporting only
the pooled figure hides that the effective sample of the difficult problem is 13. Both
numbers go in: the pooled one and the hard-subset one. The data already exists.

### 3. A robustness run with `--top 10`

The A+B rule currently acts on three cases, all inside one fork already present in the
sample — a temporal replication, not validation on unseen forks. `--top 10` brings roughly
43 previously unseen forks. Cost: ~15 minutes of machine time plus API budget. It changes
whether the rule can be *recommended* or only *described*.

### 4. Rename Layer 1 to what it is

`layer1_sha()` performs `upstream_post == fork_content`. Either rename it to literal
content comparison — which is what it does, and it works exactly as well — or actually
hash. **We will rename.** Hashing adds nothing here, and a name that misdescribes the code
is free ammunition for the next reviewer. The rename lands in the code and in every figure
and table caption that mentions "SHA".

### 5. Take the embedding layer out of the method

It measures proximity in a vector space, not semantic equivalence, and **it has not run
since July 2026**. Two honest options: remove it from the method and present it as future
work, or reintegrate it and re-measure everything. **We will remove it.** The current run
is defensible without it, and bringing it back would reopen the whole validation.

### 6. One vocabulary, defined once

Choose between `NAO_CORRIGIDO` and `VULNERAVEL`, and between `ZONA_INCERTEZA` and
`AMBIGUOUS`. Today the first of each pair is a pipeline verdict and the second a
ground-truth label; if both are kept, the text must say so explicitly the first time each
appears.

### 7. Rewrite the method chapter without the overstated claims

No "SHA-256", no "semantic layer", no novelty claim for the uncertainty zone. Thresholds
presented as a policy choice, with E2 and E6 supporting them, and separated from the
experimental setup.

### 8. Related work: add FIBER, VUDDY, Movery, V1scan

With the reason each one is or is not a direct baseline. Fix the citations that do not
support their sentences, and complete the language column of the comparison table — that
column actually **favours** this work, since operating across six languages is a real
differentiator.

### 9. Fold E1–E6 into the results chapter

The experiments are already written and reproducible offline. The trivial baseline belongs
in the **main** table, not an appendix; the confidence intervals accompany every headline
figure; the failure analysis becomes a section of its own.

### 10. Reopen the decision on the A+B rule, with Kappa on the table

The current project position — "it buys precision at the cost of one true positive" — is
true but incomplete: the rule has the **best Kappa under both oracles** (0.778 / 0.717) and
the best accuracy. Against it: E6 shows `thr_high = 0.95` reaches the same operating point
without any new mechanism, and the human oracle shows one of its three decisions was wrong.
This is a decision to take deliberately, not to inherit.

---

## 5. Claims retired from the text

These were stated in earlier versions of this package and its documents. They are **wrong**
and must not reappear:

1. ~~"Layer 1 is a SHA-256 hash comparison."~~ It is a literal string comparison.
2. ~~"The uncertainty zone is absent from existing approaches."~~ Classification with a
   reject option is classical.
3. ~~"The semantic layer, based on embeddings…"~~ It is not semantic, and it has not run
   since July 2026.
4. ~~"Kappa 0 is a property of the population."~~ Refuted: Kappa rose to 0.590 on the
   *same* population once the evidence-discarding defect was fixed. Observed agreement went
   0.657 → 0.875 while chance agreement went 0.665 → 0.695 — the imbalance did not change.
5. ~~"Zero false positives."~~ The 2026-08-17 run produced 7; the current run produces 2.
6. ~~"The A+B rule eliminates false positives at no cost."~~ Under the human oracle it
   costs one true positive, and it is decided on three cases in two forks.
7. ~~"The union outperforms the baselines."~~ It leads by one pair, and E4 shows no
   difference at n=40 is statistically distinguishable.

## 6. Is it worth resubmitting?

Yes — but not the same paper. A submission built on this material needs: one real
population, the trivial baseline in the main table, confidence intervals and paired tests,
threshold cross-validation, a failure analysis, and a second annotator.

**Five of those six now exist.** The one missing is item 1 of §4 — the one that requires
another person.
