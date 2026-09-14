# Code tour — following the method through the source

A guided walk through this repository in **execution order**, mapping each stage of the
method to the file, the function and the line that implements it. Written to be read beside
the code, top to bottom, in about fifteen minutes.

Every line reference points at the file as versioned here. Where the code and the prose in
older documents disagree, **the code is the authority** — and this tour says so explicitly
wherever that happens.

**Convention of this package:** module docstrings are in English; verdict labels, CSV column
names and some inline comments stay in Portuguese because they are literal values written
into every result file (see the glossary in `README.md`).

---

## The map in one screen

```
Stage 1 — mining                Stage 2 — population           Stage 3 — verification
─────────────────────           ─────────────────────          ──────────────────────
fase1_fix_commits.py            pipeline_dissertation.py       pipeline_core.py
  (or pipeline1.py)               select_top_forks()             parse_code / _norm
        │                         select_patch_files()           levenshtein / zss_dist
        ▼                                 │                      compute_sim
cves-fixing-commits-dataset.csv           ▼                      classify / classify_dual
        └──────────────────────►  process_upstream() ──────────────────┘
                                          │
                                          ▼
                            dissertation_resultados.json   ← every number derives from this
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
     ground_truth.py              auditoria_manual.py         experimentos_revisores.py
   (automated oracle)               (human oracle)          experimento_regra_ab.py
                                                            sensibilidade_regras.py
                                                            metricas_subconjunto_dificil.py
                                                            trabalhos_relacionados/rw1..rw6
```

**The one file to understand first** is `dissertation_resultados.json`: one record per
(fix commit × file × fork), carrying the similarities and the labels. Everything downstream
— both oracles, every experiment, every baseline, every figure — re-derives from it without
touching the network. That is what makes the offline reproduction possible.

---

## Stage 1 — from CVE to fix commit

**File:** `fase1_fix_commits.py` (the one used for this run) · alternative: `pipeline1.py`

| Step | Where | What happens |
|---|---|---|
| query the advisory | `refs_do_ghsa()` / `refs_do_nvd()` | GitHub Advisory Database first, NVD as fallback |
| extract commit URLs | `shas_das_refs()` | regex over the advisory references, **in order of appearance** |
| validate the SHA | `stats_do_commit()` | asks the *target* repository whether the commit exists; 404 discards |

Read the docstring of `shas_das_refs()` — it explains the one non-obvious decision here: the
URL is **not** filtered by the owner it declares, because renamed repositories publish
references under the old owner. Since the SHA is a content hash, validation is a question to
the target repo, not a string comparison. That is what recovered `poljar/matrix-nio` after
its transfer to `matrix-nio/matrix-nio`.

**Output:** `cves-fixing-commits-dataset.csv`, one row per **CVE × fix commit**. Several CVEs
have more than one row — backports and cherry-picks — which is what makes the union rule in
Stage 3 necessary.

---

## Stage 2 — choosing the population

**File:** `pipeline_dissertation.py`

### Which forks — `select_top_forks()` (line 352)

The question is about *divergent* forks, so the ranking is not "most recently pushed". The
function pages through the forks, then uses the compare API to keep those with commits of
their own (`ahead_by > 0`), active within the window, and returns the top N.

Constants at lines 102–107: `TOP_FORKS = 3`, `DAYS_WINDOW = 730`, `FORK_PROBE_LIMIT = 80`.

> **Declare this when presenting:** selection runs against the live API, so the same command
> months later will **not** select the same forks. Published numbers reproduce from the
> versioned run folder, never by re-running Stage 2.

### Which files — `select_patch_files()` (line 237)

Returns up to two files per fix commit: the highest-churn **production** file and the
highest-churn **test** file (`is_test_file()`, line 212; non-source extensions filtered at
line 231). Both are evaluated and their verdicts unioned later.

> `select_patch_file()` (singular, line 281) is the older one-file version, kept for
> reference. The pipeline calls the plural.

---

## Stage 3 — the verifier

### The core — `pipeline_core.py`

Read this file in this order; it is the heart of the method.

| Line | What to look at |
|---|---|
| 54–57 | the four decision constants: `ZSS_NODE_LIMIT = 600`, `THRESHOLD_HIGH = 0.80`, `THRESHOLD_LOW = 0.35`, `MARGIN_ZI = 0.05` |
| 110–148 | the normalisation sets: `_IGN` (comments, discarded), `_VARS` → `VAR`, `_STRS` → `STR`, `_NUMS` → `NUM`, `_LOOPS` → `LOOP` |
| 186 | `_norm()` — the recursive normalisation. **This is the conceptual centre**: it erases renaming, literals and comments while preserving control structure |
| 200 | `parse_code()` — tree-sitter, grammar chosen by the file's real extension |
| 180 | `inorder()` — flattens the tree so sequence edit distance applies |
| 255 | `levenshtein()` — delegates to rapidfuzz when available; the pure-Python loop is the fallback, and the distance is identical |
| 278 | `zss_dist()` — tree edit distance, returns `None` above the 600-node limit |
| 297 | `compute_sim()` — combines: `0.45 × lev + 0.55 × zss`, or `lev` alone |
| 345 | `classify()` — the three-way Layer 2A label |
| 361 | `classify_dual()` — the delta and the Layer 2B label |

> **Say this before the professor finds it:** the 0.45 / 0.55 weights have **no documented
> justification** anywhere in the repository. On this run they apply to 3 of 63 comparisons,
> because the other 60 exceeded the 600-node limit and fell back to Levenshtein alone. That
> limit is not only a memory guard — it decides *which metric is used*.

### The three layers — `pipeline_dissertation.py`

| Line | Function | Layer |
|---|---|---|
| 288 | `layer1_sha()` | **Layer 1** — literal content comparison. It is `upstream_post == fork_content`; **nothing is hashed**, the name is historical |
| 293 | `layer2a()` | **Layer 2A** — AST similarity against the post-patch reference only |
| 305 | `layer2b()` | **Layer 2B** — dual reference; returns `sim_patch`, `sim_vuln`, `delta`, label |

### The main loop — `process_upstream()` (line 398)

This is the function to read line by line; it contains every possible path a pair can take.
The order of the tests *is* the algorithm:

1. file missing in the fork → `FILE_NOT_FOUND`, record written, path ends
2. Layer 1 matches → `CORRIGIDO`, record written, path ends (2A and 2B never run)
3. Layer 2A runs; a parse failure yields `UNSUPPORTED` — an **abstention**, not a verdict
4. Layer 2B runs only if the pre-patch file exists, otherwise `NO_PRE_PATCH` — also an abstention
5. `decidir_status()` combines them

### The combination — `decidir_status()` (line 549)

Six lines of code that decide everything:

```python
if label_2b in ("CORRIGIDO", "VULNERAVEL"):    return label_2b
if label_2a in ("CORRIGIDO", "NAO_CORRIGIDO"): return label_2a
return "ZONA_INCERTEZA"
```

Layer 2B wins when conclusive, because it saw **both** references and 2A saw one. Above it,
line 546 holds `SIM_MINIMA_2B = 0.60` and the block documents the optional `--regra-ab`
guards, which refuse a doubtful `CORRIGIDO` instead of inverting it.

> **The cell where the false positives come from:** 2A says patched, 2B lands in the
> uncertainty zone, and the result is patched. Both false positives of this run entered
> there. Guard A is what intercepts it.

### From records to verdicts

| Line | Function | What it does |
|---|---|---|
| 609 | `_STATUS_PRIORITY` | `CORRIGIDO 4 > ZONA_INCERTEZA 3 > VULNERAVEL = NAO_CORRIGIDO 2 > FILE_NOT_FOUND 1` |
| 622 | `aggregate_verdicts()` | one verdict per (fork, CVE) — union across files **and** fix commits |
| 654 | `compute_coverage()` | % of the upstream's CVEs patched in each fork — answers RQ2 |
| 709 | `compute_metrics()` | aggregates per ecosystem category |

Two consequences of that priority table worth pointing out: **one** record saying patched is
enough for the whole pair, and **uncertainty beats vulnerable** — a pair is only declared
vulnerable when no record was patched or uncertain.

---

## The two oracles

### Automated — `ground_truth.py`

Independent of the method under test by construction: it looks for the **patch lines**, not
for AST similarity.

| Line | What |
|---|---|
| 171 | `normalize()` — strips whitespace, tabs, comments |
| 177 | `line_present()` — exact normalised match plus fuzzy, `threshold = 0.85` |
| 197 | `verify_fork_gt()` — labels a pair `CONFIRMED_PATCHED` / `CONFIRMED_VULNERABLE` / `AMBIGUOUS` |
| 296 | `load_gt_tasks()` — reads the pairs **dynamically** from `dissertation_resultados.json` |
| 352 | `calcular_metricas()` — precision, recall, F1, accuracy, Kappa |

### Human — `auditoria_manual.py`

| Line | What |
|---|---|
| 66 | `FICHAS` — the per-CVE briefing: trigger, effect, corrective anchor, where to look |
| 413 | `gerar()` — builds the HTML + CSV worklist, grouped by CVE |
| 606 | `apurar()` — recomputes P/R/F1 over the human verdicts and the agreement with the automated oracle |

Agreement on this run: **36 of 41 pairs, 87.8%**. The filled-in worklist is versioned, so
`apurar` reproduces the human oracle immediately, offline.

---

## Everything downstream is offline

None of these touch the network. They re-derive from the records already in the run folder,
which is what makes the results checkable by a third party without a GitHub token.

| Script | Question it answers |
|---|---|
| `experimentos_revisores.py` | E1 trivial baseline · E2 threshold cross-validation · E3 patch-size discriminant · E4 bootstrap CIs + McNemar · E5 failure analysis · E6 operating curve |
| `metricas_subconjunto_dificil.py` | metrics split between the hard upstream and the rest, under both oracles |
| `experimento_regra_ab.py` | what the A+B rule would have produced, re-derived from the same records |
| `sensibilidade_regras.py` | how each threshold moves precision, recall, Kappa and coverage |
| `impacto_evidencia_teste.py` | what the test-evidence defect cost, measured over the archived files |
| `trabalhos_relacionados/rw1..rw6/run.py` | each state-of-the-art technique, measured **on this same run** |

The pattern is deliberate and worth stating out loud: **a decision rule changes no
measurement.** `sim_2a`, `sim_patch`, `sim_vuln` and `delta` are already recorded, so a rule
only changes how those numbers become a label. Re-running Stage 3 against the API would
bring a different set of forks and destroy comparability — which is why every rule
experiment re-derives instead of re-running.

---

## A suggested route, with what to say at each stop

Fifteen minutes, in this order:

1. **`README.md`** — scope of the run and the headline numbers. *"One upstream per category,
   the three most active divergent forks of each, every CVE with a locatable fix commit."*
2. **`pipeline_core.py`, lines 110–200** — the normalisation sets and `_norm()`. *"This is
   why a renamed variable doesn't break the comparison."*
3. **`pipeline_core.py`, lines 345–380** — `classify()` and `classify_dual()`. *"Three states,
   not two. The uncertainty zone escalates to human audit instead of guessing."*
4. **`pipeline_dissertation.py`, `process_upstream()`** — the order of the tests. *"Every
   path a pair can take is in this loop."*
5. **`decidir_status()`, line 549** — six lines. *"And this is where the two false positives
   of the run came from."*
6. **`ground_truth.py`, line 177** — `line_present()`. *"The oracle looks for patch lines, not
   for AST similarity — that independence is what makes it a valid reference."*
7. **`resultados_2026-08-31_v2/`** — open `dissertation_resultados.json` and one file under
   `evidencias_dissertacao/`. *"Every comparison the pipeline made is archived here, so any
   verdict can be re-checked by hand."*
8. **`EXPERIMENTS.md` and `REVIEW_RESPONSE_AND_ROADMAP.md`** — what was measured and what is
   planned.

**Three things to volunteer before being asked**, because they will be found anyway: the
Layer 1 name says SHA and hashes nothing; the 0.45/0.55 weights are undocumented; and the
600-node limit decided which metric was used in 95% of the comparisons.

---

## What is *not* in this repository

- **The embedding prototype does not run.** `prototipo_ranking_embeddings/` is kept as future
  work; no current figure depends on it, and it has not executed since July 2026.
- **`pipeline.py`** exists only for history. The canonical Stage 1 is `pipeline1.py`, and the
  light version actually used is `fase1_fix_commits.py`.
- **Execution logs** are excluded by `.gitignore` because they may carry local paths.
