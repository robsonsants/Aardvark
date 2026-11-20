# Resultados

```text
resultados/
├── matrix/                    ecossistema Matrix, coleta de 18/09/2026
│   ├── top10/                 EXECUÇÃO OFICIAL: 10 forks por projeto, 460 pares
│   └── top10_regraAB/         a mesma execução sob a configuração A+B
└── validacao_externa/         Linux, FFmpeg e PHP (PatchLens), 04/10/2026
```

A pasta `top10_regraAB` é derivada por `src/experimento_regra_ab.py` das mesmas
linhas cruas, sem rede.

## `matrix/top10/`, a execução oficial

Os programas leem todos os arquivos de uma execução a partir de uma pasta só,
por isso eles ficam lado a lado. Agrupados por etapa:

**1. Verificação pelo método** (`src/pipeline_dissertation.py`)

| Arquivo | Conteúdo |
|---|---|
| `dissertation_resultados.json` / `.csv` | 770 linhas cruas, uma por combinação de *commit* de correção, arquivo e *fork*, com as similaridades de cada camada. |
| `dissertation_veredictos.json` | 460 vereditos, um por par *fork* × CVE, após a agregação. |
| `dissertation_cobertura.json` | Cobertura de cada um dos 109 *forks*. |
| `dissertation_metricas.json` | Resumo da população e cobertura por categoria do ecossistema. |
| `evidencias_dissertacao/` | Arquivos baixados (versão anterior e posterior à correção no *upstream* e versão do *fork*), uma pasta por CVE. |

**2. Gabarito automático** (`src/ground_truth.py`)

| Arquivo | Conteúdo |
|---|---|
| `gt_dissertation_resultados.json` / `.csv` | Rótulo automático de cada linha, por presença das linhas do *patch*. |
| `gt_dissertation_metricas.json` | Pares agregados e métricas contra o gabarito automático (312 pares conclusivos). |
| `evidencias_gt_dissertacao/` | Arquivos usados pelo gabarito automático. |

**3. Gabarito humano** (`src/auditoria_manual.py`)

| Arquivo | Conteúdo |
|---|---|
| `auditoria_manual_revisor1.html` | Lista de trabalho cega usada pelo revisor no navegador: para cada par, a linha que distingue a versão corrigida da vulnerável, o *commit* de correção e o arquivo do *fork*, sem o veredito do método. |
| `auditoria_manual_revisor1.csv` | A mesma lista em CSV. |
| `auditoria_manual_preenchida.csv` | **Vereditos humanos** dos 333 pares (corrigido, vulnerável ou inconclusivo), com a justificativa de cada um. É o gabarito usado na dissertação. |
| `auditoria_manual_apuracao.json` | Apuração: concordância com o gabarito automático (86,8%) e lista das divergências. |

**4. Experimentos de avaliação** (`src/experimentos_revisores.py`)

| Arquivo | Conteúdo |
|---|---|
| `experimentos_revisores_log.txt` | Saída completa: E1 camadas isoladas e classificador trivial, E2 validação cruzada dos limiares (exploratória, não reportada na dissertação), E4 intervalos de confiança e McNemar, E6 curva de operação (análise de sensibilidade). |
| `experimentos_revisores.json` | Os mesmos resultados em JSON. |

**5. Caracterização da propagação** (`src/dataset_temporal.py`, `src/tempo_correcao.py`)

| Arquivo | Conteúdo |
|---|---|
| `dataset_temporal_pares.csv` | Por par: data de criação do *fork*, datas dos *commits* de correção e *commits* à frente e atrás do *upstream*. |
| `dataset_temporal_forks.csv` | Por *fork*: criação, último *push*, *commits* à frente e atrás, número de CVEs e cobertura. |
| `dataset_temporal.json`, `dataset_temporal_log.txt` | Os mesmos dados agregados e o registro da coleta. |
| `heranca_propagacao.json` | Classificação dos 333 pares verificáveis em herança (274), propagação (55) e sem data (4), com os vereditos do método e do revisor em cada classe. |
| `tempo_correcao.csv` / `.json`, `tempo_correcao_log.txt` | Tempo até a correção nos pares de propagação, medido no grafo do Git. |

## `validacao_externa/`

Execução do método, sem alteração, sobre os ramos de manutenção do Linux, do
FFmpeg e do PHP, com as correções do conjunto de dados do PatchLens
(`src/experimento_patchlens.py`). A leitura por extenso está em
`RESULTADOS_PATCHLENS.md`.

| Arquivo | Conteúdo |
|---|---|
| `oraculo_proveniencia.json` | Gabarito por proveniência no grafo do Git: se o ramo contém o *commit* de correção ou um equivalente. |
| `linhas_cruas.jsonl` | Uma linha por verificação, com as similaridades de cada camada. |
| `pares_agregados.json` | Vereditos por par ramo × correção. |
| `metricas_patchlens.json` | Métricas por projeto e no total, com e sem herança, e verificabilidade por idade da correção. |
| `metricas_stdout.txt` | Saída original do cálculo das métricas. |
| `negativos_com_titulo_igual.json` | Checagem do oráculo: negativos com *commit* de mesmo título no ramo. Está vazio, ou seja, nenhum foi encontrado. |
