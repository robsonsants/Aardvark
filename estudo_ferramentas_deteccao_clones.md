# Study of clone-detection tools

> **Why this document exists.** The clone-detection tools must be studied *before*
> building the ground truth, because each tool's language limitations determine what can
> enter the dataset at all. The practical outcome is the **language × tool matrix**
> (section 4), which constrains which upstreams/CVEs can become ground truth in Phase 1.

---

## 1. The binding constraint: the languages of Matrix

The pipeline is a **ranked clone search**: take the *vulnerable snippet* (the code before
the fix commit) and query the indexed downstreams → **ranked list** of candidates. Only
what the chosen tool can **tokenise/parse in the upstream's language** can enter the
dataset.

| Leg | Candidate upstream | Language | Note |
|---|---|---|---|
| **server** | element-hq/synapse | **Python** | best supported by every tool |
| **library** | matrix-org/matrix-rust-sdk | **Rust** | weak support in classical tools |
| **client** | element-hq/element-android | **Kotlin** | weak/partial support |
| (iOS client) | matrix-org/matrix-ios-sdk | Swift | likewise |
| (integration/bridge) | matrix-hookshot / appservice-irc | TypeScript | partial |
| (bridge) | mautrix/* | Go | partial |

**Immediate consequence:** Python is the only language with full support across virtually
the whole toolset. Rust/Kotlin/Swift require either a *grammar-pluggable* tool (ANTLR) or
an *embedding-based* approach. That alone suggests **starting Phase 1 with the server leg
(synapse/Python)** — see section 5.

---

## 2. The tools, by class

### 2A. Token-based, Type 1–2 (the classics)

**CCFinderX** — Types 1 and 2. Native languages: Java, C, C++, COBOL, VisualBasic, C#.
Interactive environment (Kamiya). Old (~2010); maintained fork at `gpoo/ccfinderx`. No
Rust/Kotlin/Swift/TypeScript. **Does not rank** (batch pairwise detection).

**CCFinderSW** — Types 1 and 2. Multilingual via **ANTLR grammar definitions** (more
extensible than CCFinderX). Still **no Type 3** (near-miss) and no ranking.

> **Recommended role:** use CCFinder as a **baseline / motivation** — the same way the
> commit hash is used only to motivate that literal matching is insufficient. CCFinder
> (Types 1–2, no tolerance to refactoring) is the token-level analogue: it shows that
> matching tokens is not enough for divergent forks. It is **not** the main method.

### 2B. TXL-based, Types 1–2–3 (highest precision for ground truth)

**NiCad / NiCad3** (`bumper-app/nicad`, Cordy & Roy) — hybrid TXL plus normalised textual
comparison. Detects Types 1, 2 and **3 (near-miss)** at **function/block** granularity,
with **high precision and recall**. Native: **C, C#, Java, Python** (+ C++, Solidity).
Plugin architecture by naming convention, but **each new language requires writing a TXL
grammar** (expensive for Rust/Kotlin/Swift). Runs on Linux/macOS; on Windows through
**WSL/Git Bash** (it is shell scripts + TXL).

> **Recommended role:** **reference detector for the ground truth on the Python leg
> (synapse)** — it is the gold standard for precision/recall on function clones and the
> most cited in the literature, which gives methodological defensibility.

### 2C. Grammar-pluggable multilingual (to cover Rust/Kotlin/Swift/TS)

**MSCCD** ("Grammar Pluggable Clone Detection Based on ANTLR Parser Generation") —
generates the detector from **any ANTLR grammar** (ready-made grammars exist for Rust,
Kotlin, Swift, TypeScript, Go…). Detects up to Type 3 at block granularity. It is the most
realistic route for **the library/client legs** without hand-writing TXL. (See also the
2024 multilingual benchmark, arXiv:2409.06176.)

**PMD-CPD** (Copy/Paste Detector) — pragmatic, **many languages out of the box** (Java,
C/C++, C#, Kotlin, Swift, Go, JS/TS, Python, Ruby…). Types 1–2 only (token). Java CLI,
runs easily on Windows. **Role:** quick multilingual sanity check, not the main method.

### 2D. Clone search/ranking — what the pipeline actually needs

Our step 3 is *query → ranked list*, i.e. **clone search**, not batch pairwise detection.
The options:

**Siamese** (Ragkhitwetsagul & Krinke, 2019) — a scalable, incremental **clone search**
engine with multiple code representations, *query reduction* and a **custom ranking
function**. MAP of 95–99% on benchmarks; reports the highest number of **Type 3** clones
among search engines. Elasticsearch-based. Originally focused on **Java**; extending to
other languages requires adapting the normalisation.

**SourcererCC** (Sajnani, 2016) — token + **inverted index**; near-miss up to a threshold;
scalable; queries the clones of a given block. Configurations for Java, C, C#, Python;
extensible tokeniser (Kotlin reported). Fits the "index the downstreams + query the
snippet" shape well.

**NIL** (Nakagawa, 2021) — token N-grams + inverted index + LCS; **high-variance Type 3**;
very fast and scalable.

### 2E. Semantic / embeddings (Types 3–4, language-agnostic)

**UniXcoder / GraphCodeBERT / CodeBERT** — produce code *embeddings*; rank downstreams by
cosine similarity to the vulnerable snippet; cover several languages (Python, Java, JS/TS,
Go, Ruby, PHP… and adaptable to Rust/Kotlin). They capture Types 3–4 (heavy refactoring)
and align with the trajectory of this research (AST → semantics → LLM).
**Role:** the **cross-language ranking** layer, especially for Rust/Kotlin/Swift.

---

## 3. Fit to the pipeline (search vs. pairwise detection)

| Mode | Does "query → ranked list"? | Tools |
|---|:--:|---|
| **Search/ranking** (what we need) | ✅ | Siamese, SourcererCC (index), NIL, embeddings (UniXcoder) |
| **Batch pairwise detection** | ❌ (adaptable) | NiCad, CCFinderX/SW, MSCCD, PMD-CPD |

The pairwise tools remain useful: they produce the **high-precision ground truth** (NiCad)
and the **motivation baselines** (CCFinder ≈ hash).

---

## 4. Language × tool matrix (the result that constrains the dataset)

Legend: ✅ native · 🟡 possible with effort (grammar/tokeniser/adaptation) · ❌ no.

| Tool | Types | Python | Rust | Kotlin | Swift | TS | Go | Ranking |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| CCFinderX | 1–2 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CCFinderSW | 1–2 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ❌ |
| **NiCad3** | 1–2–3 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ❌ |
| MSCCD | 1–2–3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| PMD-CPD | 1–2 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ❌ |
| SourcererCC | 1–2–3⁻ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 (index) |
| **Siamese** | 1–2–3 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ |
| **Embeddings (UniXcoder)** | 3–4 | ✅ | 🟡 | 🟡 | 🟡 | ✅ | ✅ | ✅ |

**Key readings:**
1. **Python is the only "all ✅" language.** This confirms starting Phase 1 with the
   **server (synapse)** leg.
2. For **Rust/Kotlin/Swift** the realistic options are **MSCCD** (ANTLR) or **embeddings**
   — not the classics (NiCad/CCFinder) without grammar work.
3. The **ranking** mode we need genuinely exists in Siamese / the SourcererCC index /
   embeddings — not in plain NiCad or CCFinder.

---

## 5. Recommendation and next actions

**Architecture recommendation (Phase 1):**
- **Initial leg:** **server / synapse / Python** — avoids the language barrier and lets the
  methodology be validated immediately.
- **Ground-truth detector:** **NiCad3** (Types 1–3, function level, high precision).
- **Search/ranking engine (the main method):** start with **embeddings (UniXcoder)** for
  the *query → ranked downstreams* step, since it is language-agnostic and already prepares
  the Rust/Kotlin legs; compare with **Siamese** once an Elasticsearch environment exists.
- **"Motivation" baseline:** **CCFinderX/SW** (Types 1–2) plus the **hash** — both show the
  insufficiency of literal matching in divergent forks.
- **Multilingual sanity check:** **PMD-CPD**.

**Concrete next actions (leading into building the ground truth):**
1. [ ] Install and validate **NiCad3** and **PMD-CPD** on Windows (NiCad via WSL/TXL); run
   on one synapse CVE as a pilot.
2. [x] Prototype the **embedding ranker (UniXcoder)**: index N synapse forks, query with the
   pre-fix snippet of one CVE, and check whether the correct fork ranks at the top.
   *(Done — `prototipo_ranking_embeddings/run.py`.)*
3. [x] Reuse the **baselines already available** in `trabalhos_relacionados/` (hash rw1,
   AST rw2, dual reference rw3) as the comparison against the ranker.
   *(Done — `trabalhos_relacionados/resultados_2026-07-08/RESUMO.md`.)*
4. [x] Only then **build the ground truth**, respecting what the tool can find and
   **excluding oversized CVEs** (e.g. matrix-ios-sdk, 44 files / 2595 lines).
   *(Done — see `resultados_2026-07-04/VALIDACAO_GROUND_TRUTH.md`.)*

---

## References

- NiCad3 — [github.com/bumper-app/nicad](https://github.com/bumper-app/nicad) ·
  [txl.ca/txl-nicaddownload](http://www.txl.ca/txl-nicaddownload.html) ·
  [The NiCad Clone Detector, ICPC'11 (PDF)](https://www.cs.usask.ca/~croy/papers/2011/CR-NiCad-Tool-ICPC11.pdf)
- CCFinderSW — [Clone Detection with Flexible Multilingual Tokenization (Osaka, PDF)](https://sel.ist.osaka-u.ac.jp/lab-db/betuzuri/archive/1104/1104.pdf) ·
  [IEEE Xplore](https://ieeexplore.ieee.org/document/8305997/) · CCFinderX fork: [github.com/gpoo/ccfinderx](https://github.com/gpoo/ccfinderx/blob/master/README.md)
- MSCCD — [Grammar Pluggable Clone Detection (ANTLR)](https://www.researchgate.net/publication/359728491_MSCCD_Grammar_Pluggable_Clone_Detection_Based_on_ANTLR_Parser_Generation) ·
  [Benchmarking multilingual clone detector, arXiv:2409.06176](https://arxiv.org/pdf/2409.06176)
- SourcererCC — [Scaling Code Clone Detection to Big Code, arXiv:1512.06448](https://arxiv.org/pdf/1512.06448)
- Siamese — [Scalable and incremental code clone search (Springer EMSE)](https://link.springer.com/article/10.1007/s10664-019-09697-7) ·
  [AAM PDF](https://cragkhit.github.io/publications/2019_siamese_aam.pdf)
- Multilingual landscape 2024–2025 — [analysis-tools.dev](https://analysis-tools.dev/tag/swift) ·
  [CodeQL Kotlin/Swift GA](https://github.blog/changelog/2024-07-26-codeql-2-18-1-kotlin-swift-mobile-support-is-generally-available-typescript-5-5-support-c-build-mode-none-public-beta/)
