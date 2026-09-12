# The experimental arc, in order

Every experiment this study ran, in the order it ran, with what each one asked, how it was
executed, what it produced, and **what survived** — because several of these results were
later overturned, including by our own defect.

Read this alongside two other documents: `RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md` has the
method at procedure level (July state), and `RESULTS_2026-08-31.md` has the current
numbers. This file is the narrative that connects them.

**How to read each entry.** *Question* — what it asked. *Why* — what forced it.
*Procedure* — how it ran. *Result* — what it produced, always tagged with the run it was
measured on. *Status today* — whether it still holds.

**A warning that applies throughout.** Numbers are tagged with their run for a reason.
Every run before `2026-08-31_v2` was produced by a pipeline that silently discarded the
test-file evidence (`CHANGELOG.md` §1), so those figures **underestimate the method**. They
are kept here because the reasoning that followed from them is part of the record, not
because they are still true.

---

## Timeline

| # | Experiment | When | Status today |
|---|---|---|---|
| 0 | Related work reproduced as executable baselines | Jul | **valid**, re-measured on the current run |
| 1 | Clone-detection tool study | Jul | valid as a design decision |
| 2 | Embedding prototype, single CVE | Jul | prototype; not part of the method |
| 3 | Embedding scale-up to the ecosystem | Jul | **superseded** — see the caveat |
| 4 | Precision on a constructed two-class set | Jul | **abandoned population** |
| 5 | Preparing the manual audit | Jul | infrastructure, never filled in as designed |
| 6 | Human audit of the ground truth + anchored GT v2 | Jul | valid |
| 7 | Ecosystem census and real scale (runs 08-17, 08-18) | Aug | **superseded** by the corrected run |
| — | **The defect that reset everything** | 31 Aug | the pivot of the whole project |
| 8 | Comparison scope: file vs. declaration | Aug | **partially overturned** (see 11 Sep) |
| 9 | The A+B rule | Aug | valid, with caveats |
| E1–E6 | Validation experiments answering peer review | 8 Sep | **valid** |
| — | Declaration scope under the human oracle | 11 Sep | overturns part of Exp 8 |
| — | Metrics split by difficulty | 11 Sep | **valid** |

---

## Exp 0 — Related work reproduced as executable baselines

**Question.** How much does each state-of-the-art technique detect **on our data**?

**Why.** Without this, the related-work table is a list of citations. With it, each paper
becomes an executable baseline measured on the same corpus, and the pipeline's contribution
becomes quantified instead of argued.

**Procedure.** Each technique implemented in isolation under `trabalhos_relacionados/rwN_*/`,
applied to the already-mined dataset, verdict unioned across files and commits, measured
against the ground truth. rw1–rw4 derive from signals already recorded (no network); rw5
mines commit dates.

**Result — measured on the July run (34 pairs), superseded:**

| Technique | Recall |
|---|---:|
| whole-file hash (Wyss 2022) | 0.147 |
| patch-presence test, dual reference (PPTFI 2024) | 0.324 |
| normalised AST (VERCATION 2025) | 0.676 |

Plus: greedy set cover (See 2025) → coverage ceiling 68.8% with 5 forks; technical lag
(Decan 2018) → median 244 days (n=29).

**Re-measured 2 Sep 2026 on the corrected run — these are the current figures:**

| Technique | July | **Current** |
|---|---:|---:|
| whole-file hash | 0.147 | **0.091** |
| dual-reference PPT | 0.324 | **0.758** |
| single-reference AST | 0.676 | **0.879** |
| **union of the layers (pipeline)** | 0.676 | **0.909** |

> **A defect in the measurement rig itself, fixed here.** `load_gt_pairs()` returned all 40
> conclusive pairs as the recall denominator, with a docstring asserting "all of them are
> CONFIRMED_PATCHED" — true until July, false once the population contained negatives. The
> correct denominator is the **33 CONFIRMED_PATCHED** pairs.

**Status today: valid.** Literal matching is insufficient (0.091) — the premise of the work
is confirmed empirically rather than assumed. **Mandatory caveat:** the union beats the best
single layer by **one pair** (30 vs 29 of 33). Real, in the expected direction, not robust
at n=33, and not licence for strong language.

---

## Exp 1 — Clone-detection tool study

**Question.** Which clone-detection tools apply to the languages of the Matrix ecosystem?

**Why.** An explicit request from the committee, and a project risk: language support
constrains the dataset. A superb tool that only handles Java is useless here.

**Procedure.** A language × tool matrix crossing Python/Rust/Kotlin/Swift/TS/Go against
CCFinder, CCFinderSW, NiCad, MSCCD, SourcererCC, NIL and Siamese, classifying each by mode
of operation (pairwise detection vs. ranked search).

**Result.** **Python is the only language fully supported by all of them.** Rust, Kotlin and
Swift require a grammar-pluggable tool (MSCCD/ANTLR) or embeddings.

**Status today: valid as a design decision.** It is what sent the work down the
tree-sitter path rather than an off-the-shelf clone detector. → `estudo_ferramentas_deteccao_clones.md`

---

## Exp 2 — Embedding prototype on a single CVE

**Question.** Do code embeddings resolve the AST's false negatives?

**Why.** The AST was leaving entire cases in the uncertainty zone — on synapse (Python)
recall was 0/3.

**Procedure.** For one CVE: extract the changed function pre- and post-fix with tree-sitter,
use the diff fragment as the reference, align inside the fork's matching function with a
sliding window, decide by dual semantic reference.

**Result.** On **CVE-2024-31208**, which the AST had left entirely in the uncertainty zone,
all **3 forks classify as patched** with Δ +0.185, and sanity checks on the upstream itself
pass.

**Status today: prototype only.** The embedding layer **has not run since July 2026** and is
not part of the method as reported. See `REVIEW_RESPONSE_AND_ROADMAP.md` §4.

---

## Exp 3 — Embedding scale-up to the ecosystem

**Question.** Does the Exp 2 gain hold across all CVEs × forks of the five categories?

**Result (recall, 34 pairs of the July run):**

| Method | Recall |
|---|---:|
| hash | 0.147 |
| dual reference | 0.324 |
| AST | 0.676 |
| embeddings | **0.794** |
| union AST ∪ embeddings | **1.000** |

Complementarity by category (TP/n) is the interesting part: AST wins on Kotlin (9/9) and one
TypeScript project (10/10); embeddings win on Python (3/3 vs 0/3) and Rust (9/9 vs 1/9).

> **⚠ How to cite this — it is the most misusable number in the project.** That 1.000 is the
> recall of a union measured on 34 pairs of a set with **no conclusive negatives**, with
> thresholds chosen while looking at that same set, by a layer that **participated in no
> August run**. It is not comparable to the re-measured baselines in Exp 0, nor to any
> current figure. In the dissertation it is a **promising direction**, never a result of the
> method.

**Status today: superseded**, and the reason matters. The observation that survives is the
*complementarity* — different methods fail on different languages — not the 1.000.

---

## Exp 4 — Precision on a constructed two-class set

**Question.** What is the real precision? (Exp 3 measured only recall.)

**Why.** High recall with unknown precision is useless in security. At that point the ground
truth contained **only positive examples**, so precision was literally unmeasurable without
constructing negatives.

**Procedure.** Build a two-class set: positives = upstream at the fix commit plus forks
confirmed patched; **constructed negatives** = upstream at the **parent** commit (vulnerable
by construction) plus forks at their pre-adoption version.

**Result.**

| Method | P | R | F1 |
|---|---:|---:|---:|
| AST 2A | 0.477 | 0.932 | 0.631 |
| AST 2B | 0.559 | 0.750 | 0.641 |
| Embeddings | 0.553 | 0.955 | 0.700 |
| union | 0.489 | 1.000 | 0.657 |

**Key diagnosis.** On *clean* negatives (upstream at the parent commit, vulnerable by
construction) embeddings err on 13% of cases against the AST's 47%. The aggregate collapse
comes from the **fork pre-adoption negatives**, which are noisy: a "pre-adoption" fork may
already contain the fix by another route.

**Three methodological conclusions, all of which still hold:** the aggregate ≈0.5 is a
**floor**, not the real precision; **the margin does not fix false positives** (plateau
≈0.55) — it is not a calibration problem; and the "zero false positives" claimed at the time
was an **artefact of a positives-only ground truth**.

**Status today: the population is abandoned.** This constructed set is exactly what the peer
reviews identified as the central flaw, and the current run replaces it with **7 natural
negatives**. The experiment is kept because its diagnosis — date-based negative sets are
unreliable — is a finding in its own right.

---

## Exp 5 — Preparing the manual audit

**Question.** How to obtain definitive precision, given that the aggregate is a noisy floor?

**Procedure.** Generate a worklist of the 56 negatives (46 of them *disputed* — some method
called vulnerable code patched), with links to the fix commit and to the fork's file, and
blank columns for the human verdict.

**Status today: the infrastructure lives on, the plan did not.** That worklist targeted the
constructed negatives, which were abandoned. The machinery became `auditoria_manual.py`,
which audits the **real** population instead — see Exp 6 and the current run's human oracle.

---

## Exp 6 — Human audit of the ground truth + anchored GT v2

**Question.** Is the ground truth valid? Do "patched" verdicts rest on the line that
**actually fixes** the flaw, or on noise?

**Why.** A metric measured against a bad ground truth is a metric without meaning.

**Procedure.** (1) Navigable worklist of the 43 pairs. (2) Human audit, prioritising the 11
false negatives. (3) Assisted check of those 11: download the real diff of the fix commit and
the fork's file at HEAD, verify presence of the line that effectively corrects — not imports.
(4) **GT v2**: extract one corrective anchor per CVE and revalidate all 43 pairs **offline**
against the archived evidence.

**Result.** The **9 "ambiguous" pairs of GT v1 were an artefact of import matching**.
Anchored on the corrective line, they resolve.

**Status today: valid**, and it is the origin of the two-oracle discipline the project now
follows: an automated ground truth and a human one, always reported side by side, never
mixed. Reproduce offline with `python gt_v2_anchors.py --check`.

---

## Exp 7 — Ecosystem census and real scale (runs 08-17 and 08-18)

**Question.** What does the method do at ecosystem scale, rather than on five hand-chosen
projects?

**Procedure.** Census of 160 repositories → eligibility filter (has a CVE, has a divergent
fork, has a supported language) → Phase 1 through the GitHub Advisory DB → Phase 2 over
everything eligible. Run 08-17 took the eligible set (12 upstreams); run 08-18 took the
selection requested by the supervisor (26 positions, of which 7 were verifiable).

**Result — coverage:**

| Run | Upstreams | Forks | CVEs | Verifications | Mean coverage |
|---|---:|---:|---:|---:|---:|
| 2026-07-04 | 5 | 14 | 16 | 43 | 58.9% |
| **2026-08-17** | 12 | 33 | 39 | 105 | **67.2%** |
| 2026-08-18 | 7 | 21 | 17 | 51 | 59.1% |

**Result — reliability, and the bad news:** run 08-17 gave P 0.885 · R 0.783 · F1 0.831 with
**7 false positives — the first in the project's history.** The "zero false positives" claim
died here, and the diagnosis identified two distinct mechanisms:

1. **Layer 2A reading high with a negative delta (5 cases).** On a monolithic file a tiny
   patch leaves `sim_2a` as high as 0.987 while the fix is absent. The correct signal was in
   Layer 2B — the fork is closer to the *pre*-patch code.
2. **Layer 2B deciding on the edge of its margin (2 cases).** Very divergent forks
   (`sim_2a` 0.47–0.56) with deltas of 0.0516 and 0.0539 against a margin of 0.05. Without a
   floor on absolute similarity, the delta in that regime is noise.

Two further findings: the supervisor's ranking criterion **selects projects that have no
CVEs** (it orders by number of divergent forks, which is orthogonal to having a CVE
history), and **30 of 72 CVEs have no public fix commit** — a ceiling on data, not on method.

**Status today: superseded** by the corrected run, but the two failure mechanisms are exactly
what Exp 9 was built to address.

---

## The defect that reset everything (31 Aug)

Not an experiment — the pivot of the project, and it belongs in this sequence.

`already_processed()` keyed records on `(upstream, cve, fork, fix_sha)` **without the file
path**. Since `select_patch_files()` returns the production file first and the test file
second, the test record was treated as already processed and **silently dropped**. The union
of production and test evidence that the methodology documented **never happened in any
earlier run**. Nothing crashed; nothing appeared in any log; evidence simply vanished.

Measured offline over the archived evidence (`impacto_evidencia_teste.py`, so the fork set
stays comparable): **26 verdicts change.**

| Same configuration, same forks | Recall | Kappa |
|---|---:|---:|
| run 2026-08-18 (with the defect) | 0.710 | −0.024 |
| run 2026-08-31_v2 (fixed) | **0.909** | **0.590** |

**This retired a claim that had been repeated throughout the project:** that the near-zero
Kappa was a property of the population. It was not. Kappa rose on the *same* population once
evidence stopped being discarded — observed agreement 0.657 → 0.875 while chance agreement
went 0.665 → **0.695**. The imbalance did not decrease; the implementation was wrong.

Everything measured before this date underestimates the method, which is why every number in
this file carries its run.

---

## Exp 8 — Comparison scope: file vs. declaration

**Question.** Does the scope in which similarity is computed — whole file vs. the declaration
containing the hunk — change reliability?

**Origin.** The publication of **PatchLens** (Paixão et al., FSE 2026). Two readings were
taken from it. First, **positioning**: PatchLens answers "which *compilation variants*
contain the flaw?" (`#ifdef`, Kconfig/Make, C/C++) while we answer "which *divergent forks*
already received the fix?" — and its related work, entirely about configurable systems, does
not cover patch propagation in forks. Second, the **transferable mechanism**: mapping each
hunk to its AST nodes, which is what was reproduced.

**What was deliberately not reproduced.** The Vulnerability Impact Condition. It requires
unpreprocessed C/C++ with conditional compilation and build-system analysis; the Matrix
ecosystem has no compile-time variability, so computing a "VIC" here would produce a number
with no referent.

**Procedure.** Unlike rw1–rw5, rw6 does **not** derive from recorded signals: it redoes
Layer 2 over the code on disk, changing only the scope. Evaluated on the 78 conclusive pairs
of run 08-17.

**Result (run 08-17):**

| Scope | TP | FP | FN | TN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| file (pipeline) | 54 | 7 | 15 | 2 | 0.885 | 0.783 | 0.831 |
| **hunk → declaration** | 60 | **3** | 9 | 6 | 0.952 | 0.870 | 0.909 |
| hunk + guard A (δ ≥ 0) | 60 | **0** | 9 | 9 | **1.000** | 0.870 | **0.930** |

The 4 true positives lost have identified causes, and they are informative: three are a hunk
sitting **at the top of the file, outside any declaration** — the same failure class
PatchLens reports for PHP and for header changes — and one is a declaration whose similarity
(0.601) clears Layer 2B but not Layer 2A's 0.80 threshold.

**A side effect that changed how the method must be described.** At file scope, **116 of 125**
comparisons fell back to `lev_only` because the trees exceeded `ZSS_NODE_LIMIT = 600`. That
limit was not a memory guard — it was deciding *which metric was used* in 93% of cases. At
declaration scope the subtrees fit and Zhang-Shasha actually contributes. (On the current run
the same count is **60 of 63, 95%**.)

**Status today: partially overturned.** See the 11 September entry — the claim that
declaration scope improves precision and recall simultaneously holds under the automated
oracle and **fails under the human one**.

---

## Exp 9 — The A+B rule

**Question.** Can the false positives of Exp 7 be eliminated **without losing recall**, by
changing only how verdicts are combined?

**Procedure, and why it is built this way.** The rule adds two guards — (A) Layer 2A only
counts as patched when δ ≥ 0; (B) Layer 2B only decides when `sim_2a` ≥ 0.60 — and it does
not invert verdicts: it *refuses* a doubtful "patched" and sends the pair to human audit.
The differential was **re-derived over the same raw records** (`experimento_regra_ab.py`, no
network). That matters methodologically: the rule changes no measurement, only how
measurements become verdicts. Re-running Phase 2 against the API would bring a **different
set of forks** (selection is dynamic) and the differential would stop isolating the rule.

**Result — reliability:**

| Run | Rule | TP | FP | FN | TN | P | R | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 08-17 | union | 54 | **7** | 15 | 2 | 0.885 | 0.783 | 0.831 |
| 08-17 | **A+B** | 54 | **0** | 15 | 9 | **1.000** | 0.783 | **0.878** |
| 08-18 | union | 22 | **3** | 9 | 1 | 0.880 | 0.710 | 0.786 |
| 08-18 | **A+B** | 22 | **0** | 9 | 4 | **1.000** | 0.710 | **0.830** |

It zeroes false positives on both sets and **the true positives do not move** — the entire F1
gain comes from precision.

**Result — the price, in coverage:** 67.2% → 62.5% (08-17) and 59.1% → 56.0% (08-18),
**concentrated in the `sdk` category** (35.6% → 21.6%). Bridge, client, server and support do
not move at all, which makes sense: the monolithic files and the very divergent forks are in
the SDK.

**A correction worth keeping.** An intermediate count *by line* suggested a recall gain
(TP 60→61). Computed exactly, **aggregated by pair**, recall does not change. It is a
concrete example of why metrics must be computed at the unit of analysis, not over raw rows.

**Status today: valid, with caveats that must travel with it.** It was designed by looking at
the false positives of run 08-17, so it is not independently validated; `SIM_MINIMA_2B = 0.60`
is chosen, not derived; on the current run the three cases where it acts are all in one fork
already present in the sample — a temporal replication, not validation on unseen forks. And
E6 below shows a higher threshold reaches the same operating point without the rule.

---

## E1–E6 — Validation experiments answering peer review (8 Sep)

An earlier version of the study was submitted and rejected; the three reports converged on
one criticism: recall measured on an all-positive population and precision on a constructed
set, with no comparison against a constant classifier. `experimentos_revisores.py` answers it
with measurements, under both oracles, offline.

- **E1 — the trivial baseline.** Always answering "patched" gives F1 0.904 against the
  union's 0.923. The reviewer was right that the F1 gap is small (+0.019). What separates
  them is **Kappa (0.000 vs 0.590)** and **false positives (7 vs 2)**. On an 82.5%-positive
  population, F1 is the wrong metric — and that can now be shown rather than argued.
- **E2 — threshold cross-validation.** Leave-one-upstream-out and stratified k-fold. Good
  news: the thresholds are **not overfitted** (out-of-sample F1 0.941 vs 0.923). Bad news:
  they are **not identifiable** — every fold picks 0.60 under the automated oracle, four of
  five pick 0.90 under the human one. And the difficulty is concentrated: four of the five
  upstreams are perfect with *any* threshold.
- **E3 — is patch size a usable discriminant?** No: to zero the 2 false positives it drags 18
  cases into the uncertainty zone and halves recall. The **sign of the delta** does it by
  moving 2 — which is exactly guard A.
- **E4 — intervals and paired tests.** Bootstrap (10,000 resamples) and exact McNemar: at
  n=40 **nothing is statistically distinguishable**, including the difference from the
  trivial classifier (p = 0.727). Kappa's 95% CI runs [0.196 · 0.875].
- **E5 — failure analysis.** All five errors are in `matrix-rust-sdk`, all in Rust. The false
  positives have a clear signature (high similarity to post-patch, negative delta) and are
  detectable; the false negatives are the method working as designed — similarity ≈0.65 is
  genuinely ambiguous and escalates to audit.
- **E6 — operating curve.** 0.80 is not the F1 optimum (0.50–0.60 is, with 4 false
  positives), and `thr_high = 0.95` reproduces **exactly** the A+B operating point — a
  competing explanation for the rule's effect.

**Status today: valid.** Detail in `RESULTS_2026-08-31.md` §4.

---

## Declaration scope under the human oracle (11 Sep)

**Question.** Does the Exp 8 result hold against the human labels?

**Procedure.** `rw6 --oraculo humano --refazer-metricas`, reusing the ASTs already computed.

**Result:**

| Oracle | Scope | TP | FP | FN | TN | P | R | F1 | κ |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| automated | file | 30 | 2 | 3 | 5 | 0.938 | 0.909 | 0.923 | 0.590 |
| automated | hunk | 31 | **0** | 2 | 7 | **1.000** | **0.939** | **0.969** | 0.844 |
| human | file | 30 | 2 | 3 | 5 | 0.938 | 0.909 | 0.923 | 0.590 |
| human | hunk | 29 | 1 | 4 | 6 | 0.967 | 0.879 | 0.921 | 0.630 |

**Under the automated oracle it dominates; under the human oracle it does not** — it makes
the same precision-for-recall trade as the A+B rule. **The entire difference is one contested
pair:** `tchapgouv/matrix-rust-sdk` on CVE-2024-40648, which the automated ground truth calls
vulnerable and the reviewer calls patched. Declaration scope refuses that verdict — a false
positive removed against one label, a true positive lost against the other.

That is the case for a second annotator stated as concretely as it can be. What survives both
oracles is the Kappa gain.

---

## Metrics split by difficulty (11 Sep)

**Question.** How much of the pooled figure is owed to the easy majority?

**Procedure.** `metricas_subconjunto_dificil.py` — every metric computed separately for
`matrix-org/matrix-rust-sdk` and for the other four upstreams, under both oracles.

**Result:**

| Subset | n | P | R | F1 | κ |
|---|---:|---:|---:|---:|---:|
| hard (`matrix-rust-sdk`) | 13 | 0.667 | 0.571 | **0.615** | **0.235** |
| the other four upstreams | 27 | 1.000 | 1.000 | 1.000 | 1.000 |
| pooled | 40 | 0.938 | 0.909 | 0.923 | 0.590 |

The easy subset contains **exactly one negative** — any method scores ≈0.98 F1 there. And on
the hard subset **the trivial classifier beats the pipeline on F1** (0.700 vs 0.615); only
Kappa separates them, and that separation is real: the trivial classifier declares all six
vulnerable forks safe, the A+B rule declares none.

**Status today: valid**, and it is the strongest form of the reviewers' single-class
objection — now measured rather than argued.

---

## What the arc adds up to

Read in sequence, the experiments tell a story that is not "the method got better". It is:

1. **Literal matching is insufficient** (Exp 0) — the premise, confirmed rather than assumed.
2. **Structure helps, and different structures help in different languages** (Exp 1–3).
3. **Precision cannot be measured without negatives, and constructed negatives are
   unreliable** (Exp 4–5) — a finding that later became the reviewers' central criticism.
4. **A ground truth must be anchored on the line that actually fixes the flaw** (Exp 6).
5. **At real scale, false positives appear, and they have identifiable mechanisms**
   (Exp 7) — which killed the project's most repeated claim.
6. **Our own implementation was destroying evidence** (31 Aug) — which killed the second most
   repeated claim, that low Kappa was a property of the population.
7. **Scope and combination rules trade precision against recall, and which one wins depends
   on which oracle you ask** (Exp 8, Exp 9, 11 Sep).
8. **At this sample size, none of these differences is statistically distinguishable, and the
   difficulty is concentrated in a minority of the population** (E1–E6, 11 Sep).

That is why the framing the project now argues for is not "our pipeline detects propagation
better than the alternatives", but: **how much of the propagation of security fixes into
divergent forks is automatically verifiable — and what stops the rest.** See
`REVIEW_RESPONSE_AND_ROADMAP.md` §3.
