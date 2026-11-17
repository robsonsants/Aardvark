# Nossa metodologia sobre o dataset do PatchLens (04-05/10/2026)

> Script: `experimento_patchlens.py` (fases `oraculo`, `verificar`, `metricas`).
> Dataset: `patchlens/final_dataset.csv` (clone de github.com/fleap-dev/patchlens).
> Históricos git em `patchlens_repos/` (variável PATCHLENS_REPOS) (fora do repositório, ~1 GB).

## 1. O que foi feito e por quê

O PatchLens (Paixao et al., FSE 2026) publica 1.405 pares (CVE, commit de correção, VIC)
de **Linux (1.057), FFmpeg (280) e PHP (68)**, todos em C. O dataset responde *quais
variantes de compilação tinham a falha*; não tem forks. Para aplicar a nossa pergunta
(*este derivado recebeu a correção?*), os "forks" passaram a ser os **ramos de
manutenção** de cada produto, que são derivados divergentes com backport manual:

| produto | repositório | ramos verificados |
|---|---|---|
| Linux | gregkh/linux | 4.19.y · 5.4.y · 5.10.y · 5.15.y · 6.1.y · 6.6.y |
| FFmpeg | FFmpeg/FFmpeg | release/4.4 · 5.1 · 6.0 · 6.1 · 7.0 · 7.1 |
| PHP | php/php-src | PHP-7.4 · 8.0 · 8.1 · 8.2 · 8.3 · 8.4 |

A verificação é a do `pipeline_dissertation.py`, **importada sem alteração**:
`select_patch_files` → Camada 1 → 2A → 2B → `decidir_status` (união e Regra A+B) →
agregação por união entre commits do mesmo CVE. A única mudança no núcleo foi registrar o
parser de C em `pipeline_core._init_parsers` (de forma tolerante; nenhum upstream Matrix é
C, então os runs anteriores não mudam). A ponta de cada ramo foi fixada por SHA no início
(snapshot congelado).

**Escala:** 7.848 pares (ramo × CVE), 6.926 verificáveis, 922 FILE_NOT_FOUND (11,7%).
É **25 vezes** a população do nosso maior run Matrix (312 pares conclusivos).

## 2. O ganho metodológico: um oráculo independente do código

No Matrix, o gabarito automático é o `ground_truth.py`, que procura as linhas do patch no
arquivo do fork, ou seja, é derivado do próprio código. Aqui existe um **oráculo de
proveniência**, tirado do histórico git:

- **HERANCA**: o fix é ancestral do ponto de ramificação, então o ramo nasceu corrigido.
- **MERGE**: o fix é ancestral da ponta, mas não do ponto de ramificação (modelo merge-up do PHP).
- **BACKPORT**: um commit do ramo cita o SHA do fix (`commit X upstream`,
  `[ Upstream commit X ]`, `cherry picked from commit X`). A citação `Fixes:` fica de fora
  de propósito, porque aponta o commit que introduziu o bug.
- **SEM_CORRECAO**: nenhuma das anteriores.

No Linux, 398 dos 400 commits recentes do 6.6.y citam o SHA upstream; no FFmpeg, 302 dos
338 commits exclusivos do release/6.0.

**O oráculo de proveniência também erra, e o erro é diagnosticável.** Na inspeção manual,
pares SEM_CORRECAO tinham o código corrigido presente no ramo. A causa comum é que **o
commit do dataset não está na linha principal do produto**. No FFmpeg são 46 commits que
existem só em ramos de release, nunca no `master` (todos do mantenedor principal; a
hipótese inicial de "commits do Libav" foi checada e é falsa). No PHP são commits de ramos
antigos que não chegam aos ramos verificados por ancestralidade. Nesses casos o ramo
recebeu a correção por outro commit. Daí:

- **Proveniência refinada**: SEM_CORRECAO só conta como negativo se o fix é ancestral do
  `master`. Isso eliminou **todos os 36 negativos do PHP** e 107 dos 130 do FFmpeg.
- **Consenso**: só entram os pares em que a proveniência refinada e o oráculo por linhas
  concordam.
- Checagem extra: nenhum dos 516 negativos tem, no ramo, commit com o **mesmo título** do
  fix, então não há backport "escondido" sem citação
  (`negativos_com_titulo_igual.json` está vazio).

Ressalva que sobra: um ramo **não afetado** (o código vulnerável nunca existiu nele) conta
como SEM_CORRECAO. Para a nossa pergunta isso é correto, porque o ramo de fato não recebeu
a correção, mas não quer dizer que o ramo seja vulnerável.

## 3. Resultados

### 3.1 A herança domina, como nos forks Matrix

**6.146 dos 6.926 pares verificáveis (88,7%) são HERANCA**: o ramo nasceu depois do fix.
Nos forks Matrix eram 78% (top 10, 09-15). Sobram **780 pares em que a propagação de fato
precisa ser decidida** (649 com a proveniência refinada).

### 3.2 Onde há propagação a decidir (ramo nascido antes do fix)

Todos os produtos, proveniência refinada:

| regra | n | TP | FP | FN | TN | P | R | F1 | κ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| união | 649 | 488 | 63 | 46 | 52 | 0,886 | 0,914 | 0,900 | 0,389 |
| **Regra A+B** | 649 | 463 | **15** | 71 | 100 | **0,969** | 0,867 | **0,915** | **0,618** |
| trivial | 649 | 534 | 115 | 0 | 0 | 0,823 | 1,000 | 0,903 | 0,000 |

Só os pares de consenso dos dois oráculos:

| regra | n | TP | FP | FN | TN | P | R | F1 | κ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| união | 529 | 437 | 27 | 40 | 25 | 0,942 | 0,916 | 0,929 | 0,357 |
| **Regra A+B** | 529 | 426 | **8** | 51 | 44 | **0,982** | 0,893 | 0,935 | **0,540** |
| trivial | 529 | 477 | 52 | 0 | 0 | 0,902 | 1,000 | **0,948** | 0,000 |

Por produto, com a proveniência refinada:

| produto | regra | n | FP | P | R | F1 | κ |
|---|---|---:|---:|---:|---:|---:|---:|
| Linux | união | 577 | 44 | 0,909 | 0,909 | 0,909 | 0,431 |
| Linux | A+B | 577 | 13 | 0,970 | 0,858 | 0,910 | 0,575 |
| FFmpeg | união | 72 | 19 | 0,712 | 0,959 | 0,817 | 0,166 |
| FFmpeg | A+B | 72 | **2** | **0,959** | **0,959** | **0,959** | **0,872** |
| PHP | — | 0 | — | sem negativos válidos (só herança) | | | |

### 3.3 Achados

1. **A Regra A+B se valida fora do Matrix, num ecossistema C, contra um oráculo que não
   deriva do código.** Ela corta os FP de 63 para 15 (−76%) e quase dobra o κ (0,389 →
   0,618). No FFmpeg isso sai **sem perder um único TP**; no Linux custa 25 TP. É o mesmo
   câmbio visto no run final72 do Matrix ("compra precisão com recall"), agora com 649
   pares e um gabarito independente.
2. **O classificador trivial continua competitivo em F1** (0,903 contra 0,900 da união e
   0,915 da A+B; no consenso, 0,948 vence as duas). Só o κ separa. É a quarta medição
   independente de que **F1 é a métrica errada** para esta pergunta.
3. **A verificabilidade decai com a idade do fix**, a mesma curva do run final72 do Matrix
   e agora com n = 6.926. Proporção de pares resolvidos (fora da zona de incerteza):

   | fix em | ≤2012 | 2013-16 | 2017-19 | 2020-21 | 2022-23 | 2024+ |
   |---|---:|---:|---:|---:|---:|---:|
   | n | 1.757 | 2.337 | 1.872 | 359 | 522 | 79 |
   | resolvidos | 28,6% | 36,6% | 64,9% | 76,3% | 89,8% | 94,9% |

   É por isso que o recall na população inteira é baixo (0,424 na união): os pares de
   herança antigos caem na zona de incerteza. É abstenção, não erro. Com dois ecossistemas
   e duas linguagens, passa a ser propriedade do método, não acaso do Matrix.
4. **O nosso oráculo automático por linhas tem precisão medida pela primeira vez.**
   Contra a proveniência refinada, onde há propagação a decidir: P 0,930 · R 0,964 ·
   **κ 0,605** (n = 583). Na população inteira o κ cai para 0,068: em pares de herança
   antigos, as linhas do fix foram depois reescritas e o oráculo diz "vulnerável" ou
   "ambíguo" para ramos comprovadamente corrigidos (970 FN). **Consequência para o texto:**
   o GT automático do Matrix é razoável para CVEs recentes e se degrada com a idade, como
   o próprio método. Isso deve ser declarado como ameaça à validade.
5. **VIC trivial vs. condicional.** Nos pares de propagação, a união acerta todos os
   38 casos com VIC = `True` (P 1,000), contra P 0,879 nos 611 com VIC condicional. Com
   38 casos e 5 negativos isso **não é significativo**; fica registrado, não afirmado.

## 4. O que esta comparação é e o que não é

- **Não é** uma disputa de escore com o PatchLens: ele calcula VIC (quais configurações
  continham a falha), e nós verificamos se o derivado recebeu a correção. As perguntas
  são complementares; nenhuma das duas ferramentas responde a pergunta da outra.
- **É** um teste de **generalização externa** da nossa metodologia: outro ecossistema
  (C, sistemas configuráveis), outra escala (7.848 pares), outro tipo de derivado (ramos
  de manutenção) e, principalmente, um oráculo **independente do código**, que o estudo
  Matrix não tem.
- Combinação natural para trabalhos futuros: VIC × propagação diz *quem estava exposto
  (VIC) e se o derivado se corrigiu (nosso método)*.

## 5. Limitações

- Ramos de manutenção não são forks de terceiros: backport disciplinado e mensagens
  padronizadas tornam o oráculo possível, mas também tornam o cenário mais "limpo" que o
  dos forks Matrix.
- O PHP só contribui com herança (modelo merge-up e fixes fora do master).
- O oráculo de proveniência refinado ainda conta "não afetado" como negativo, e um backport
  sem citação nem título igual escaparia. Dos 4 negativos inspecionados à mão, 3 eram fix
  fora do master (o refinamento os remove) e 1 é erro remanescente do oráculo:
  CVE-2021-3772 no Linux 5.4.y, com as 15 linhas sondadas presentes no ramo.
- Dois commits do FFmpeg (CVE-2016-2328) estouraram a recursão do Python no `_norm` (AST
  profunda) e foram reprocessados numa thread com pilha de 255 MB (`--refazer-erros`). O
  cálculo é o mesmo.

## 6. Reproduzir

```bash
# históricos (só commits, sem blobs), fora do repositório
git clone --bare --filter=tree:0 https://github.com/FFmpeg/FFmpeg.git  ffmpeg.git
git clone --bare --filter=tree:0 https://github.com/php/php-src.git    php.git
# linux: fetch --filter=tree:0 de gregkh/linux (master + 6 ramos LTS)
git -C <repo>.git commit-graph write --reachable     # sem isso o oráculo leva horas

python experimento_patchlens.py oraculo              # ~15 min (só git)
python experimento_patchlens.py verificar --workers 8   # ~20 min (rede + AST)
python experimento_patchlens.py verificar --refazer-erros
python experimento_patchlens.py metricas             # segundos
```
