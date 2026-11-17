# Verificação Automatizada de Presença de Patches de Segurança em Forks Divergentes: Um Estudo no Ecossistema Matrix

Pacote de replicação da dissertação de mestrado de Robson de Sousa dos Santos,
Mestrado e Doutorado em Ciência da Computação (MDCC), Universidade Federal do
Ceará. Orientador: Prof. Dr. Paulo A. L. Rego. Coorientadores: Prof. Dr.
Lincoln S. Rocha e Prof. Dr. Emanuel B. Rodrigues.

## Resumo da Dissertação

Quando um projeto de código aberto corrige uma vulnerabilidade, a correção não
chega sozinha aos seus *forks*. Cada organização que mantém um *fork* divergente
precisa incorporá-la, e não há meio automático de saber se isso aconteceu. A
dissertação propõe e avalia um método que, para cada par formado por um *fork* e
uma CVE do projeto de origem, decide se o código do *fork* contém a correção. O
método minera as vulnerabilidades e os *commits* de correção no NVD e no GitHub
Security Advisories, seleciona os *forks* divergentes mais ativos e compara o
arquivo do *fork* com as versões anterior e posterior à correção em três
camadas: comparação textual (Camada 1), similaridade estrutural com referência
única (Camada 2A) e teste de presença com referência dupla (Camada 2B). O
resultado é um de quatro estados: corrigido, vulnerável, zona de incerteza ou
arquivo não encontrado.

O método foi executado sobre o ecossistema Matrix. A execução oficial cobre 16
projetos *upstream*, 64 CVEs, 109 *forks* e 460 pares, dos quais 333 puderam
ser verificados. Os vereditos foram confrontados com um gabarito automático, com
a auditoria manual dos 333 pares e com um classificador trivial, e o método foi
aplicado sem alteração aos ramos de manutenção do Linux, do FFmpeg e do PHP.

O pacote reproduz os resultados das duas questões de pesquisa:

- **QP1.** Com que confiabilidade a presença de uma correção de vulnerabilidade
  do *upstream* pode ser verificada automaticamente no código de *forks*
  divergentes?
- **QP2.** Quais são as características da propagação de correções de
  vulnerabilidades para os *forks* divergentes do ecossistema Matrix? A
  questão se desdobra em presença, herança e propagação (QP2.1), tempo até a
  correção (QP2.2) e fatores associados (QP2.3).

# Estrutura do Repositório

```text
.
├── README.md                    este arquivo
├── LICENSE                      Licença MIT
├── requirements.txt
├── .env.example                 modelo para as credenciais (não contém tokens)
├── src/                         programas
├── dados/                       entradas e coleta congelada em 18/09/2026   (ver dados/README.md)
└── resultados/                                                               (ver resultados/README.md)
    ├── matrix/
    │   ├── top10/               EXECUÇÃO OFICIAL: 16 projetos, 64 CVEs, 109 forks, 460 pares
    │   │                        verificação, gabarito automático, gabarito humano,
    │   │                        experimentos de avaliação e caracterização da propagação
    │   ├── top10_regraAB/       a mesma execução sob a configuração A+B
    │   └── top5/, top3/ e *_regraAB/   recortes aninhados da mesma coleta
    └── validacao_externa/       Linux, FFmpeg e PHP, com o oráculo de proveniência
```

Cada pasta de dados e de resultados tem um README que descreve os seus
arquivos. Os arquivos de uma execução ficam juntos numa só pasta porque é assim
que os programas os leem.

**Programas (`src/`)**

| Etapa | Programa | Função |
|---|---|---|
| Fase 1, coleta | `fase2_coletar.py` | Lê o diretório do ecossistema e coleta metadados, avisos de segurança e a rede de *forks* de cada repositório. |
| Fase 1, coleta | `censo_cpe_nvd.py` | Consulta o NVD por nome de produto e aplica a guarda de atribuição. |
| Fase 1, coleta | `fase1_fix_commits.py`, `fase1_cves_do_nvd.py` | Localizam e validam os *commits* de correção de cada CVE. |
| Fase 1, coleta | `enriquecer_cves.py` | Acrescenta CVSS e CWE e cruza severidade e ano com os vereditos. |
| Fases 2 a 4, método | `pipeline_core.py` | Normalização da árvore sintática, distâncias e classificação das camadas. |
| Fases 2 a 4, método | `pipeline_dissertation.py` | Seleciona os *forks*, extrai a evidência, aplica as camadas e agrega os vereditos por par. |
| Fases 2 a 4, método | `recorte_topn.py` | Deriva os recortes de 3 e 5 *forks* do recorte de 10, na mesma coleta. |
| Avaliação | `ground_truth.py` | Gabarito automático por presença das linhas do *patch*. |
| Avaliação | `auditoria_manual.py` | Gera a lista de trabalho cega da auditoria humana e apura os vereditos. |
| Avaliação | `experimento_regra_ab.py` | Deriva a configuração A+B das mesmas linhas cruas. |
| Avaliação | `sensibilidade_regras.py` | Varre os limiares de decisão. |
| Avaliação | `experimentos_revisores.py` | Camadas isoladas, classificador trivial, validação cruzada dos limiares, intervalos de confiança, teste de McNemar e curva de operação. |
| Avaliação | `experimento_patchlens.py` | Validação externa em Linux, FFmpeg e PHP. |
| Caracterização | `dataset_temporal.py` | Datas de criação dos *forks* e dos *commits* de correção. |
| Caracterização | `tempo_correcao.py` | Tempo até a correção medido no grafo do Git. |
| Figura | `gerar_figura_severidade.py` | Figura da distribuição de severidade das CVEs verificadas. |

# Onde Está Cada Resultado da Dissertação

Os caminhos abaixo são relativos a `resultados/matrix/top10/`, salvo indicação.

| Resultado na dissertação | Arquivos | Reivindicação |
|---|---|---|
| Funil da coleta e CVEs excluídas | `dados/fase2_2026-09-18.csv`, `dados/censo_cpe_nvd.csv`, `dados/cves-fixing-commits-dataset.csv` | #1 |
| Distribuição dos vereditos nos 460 pares | `dissertation_veredictos.json`, `dissertation_metricas.json` | #2 |
| Severidade (CVSS) e fraquezas (CWE) das CVEs verificadas | `dados/cves_enriquecidas.csv`, `dissertation_veredictos.json` | #9 |
| Desempenho contra o gabarito humano, com intervalos de confiança | `auditoria_manual_preenchida.csv`, `experimentos_revisores_log.txt` (E1 e E4) | #4 |
| Desempenho contra o gabarito automático | `gt_dissertation_metricas.json`, `../top10_regraAB/gt_regra_ab_metricas.json` | #3 |
| Contribuição de cada camada isolada | `experimentos_revisores_log.txt` (E1) | #4 |
| Vereditos por ano de publicação da CVE | `dissertation_veredictos.json` | #2 |
| Validade dos parâmetros: validação cruzada e curva de operação | `experimentos_revisores_log.txt` (E2 e E6) | #5 |
| Validação externa em Linux, FFmpeg e PHP | `resultados/validacao_externa/metricas_patchlens.json` | #6 |
| Cobertura por categoria e recortes de 3, 5 e 10 *forks* | `dissertation_metricas.json`, `../top3/`, `../top5/` | #7 |
| Herança e propagação, e desempenho nos 55 pares de propagação | `heranca_propagacao.json`, `dataset_temporal_pares.csv`, `auditoria_manual_preenchida.csv`, `../top10_regraAB/dissertation_veredictos.json` | #8 |
| Tempo até a correção (QP2.2) | `tempo_correcao.json`, `tempo_correcao.csv` | #9 |
| Fatores associados (QP2.3) | `dados/cves_enriquecidas.csv`, `dissertation_veredictos.json`, `dataset_temporal_forks.csv` | #9 |

# Informações Básicas

O artefato é um conjunto de programas Python de linha de comando, encadeados
por arquivos gravados em disco. Ele não compila nem executa os projetos
analisados.

- CPython 3.10 ou mais novo. O ambiente de referência é o CPython 3.12.6.
- Windows, Linux ou macOS.
- Um núcleo de CPU, 2 GB de RAM livres e 200 MB de disco para reproduzir as
  análises.
- Nenhum acesso à internet para reproduzir as análises a partir dos dados
  incluídos. A internet só é necessária para refazer a coleta ou a verificação.
- `git` instalado apenas para refazer o tempo até a correção e a validação
  externa, que usam clones locais.

**Todos os comandos devem ser executados na raiz do repositório**, a pasta que
contém este README. Os programas leem `dados/` e `resultados/` a partir dela.

# Dependências

As dependências estão em `requirements.txt`:

- `tree-sitter`, com os analisadores de Python, Rust, Kotlin, Swift,
  TypeScript e Go: árvore sintática das linguagens verificadas;
- `zss`: distância de edição entre árvores de Zhang e Shasha;
- `rapidfuzz`: distância de Levenshtein exata;
- `requests`: chamadas às APIs do NVD e do GitHub;
- `nvdlib`, `pandas` e `numpy`: mineração e tabulação da Fase 1.

Dois pacotes são opcionais: `tree-sitter-c`, para refazer a validação externa, e
`matplotlib`, para a figura de severidade.

Versões do ambiente de referência: tree-sitter 0.25.2, tree-sitter-python
0.25.0, tree-sitter-rust 0.24.2, tree-sitter-kotlin 1.1.0, tree-sitter-swift
0.7.2, tree-sitter-typescript 0.23.2, tree-sitter-go 0.25.0, tree-sitter-c
0.24.2, zss 1.2.0, rapidfuzz 3.14.5, pandas 3.0.2, numpy 2.4.4, requests
2.32.3 e nvdlib 0.8.1.

Recursos de terceiros acessados:

- API de CVEs do NVD, versão 2.0;
- API REST do GitHub e conteúdo bruto em `raw.githubusercontent.com`;
- diretório de projetos do ecossistema Matrix, já convertido em
  `dados/manifesto_ecossistema_matrix.csv`;
- conjunto de dados do PatchLens, em `dados/patchlens/final_dataset.csv`,
  usado só na validação externa.

# Preocupações com Segurança

Reproduzir as análises só lê arquivos JSON e CSV locais. A coleta e a
verificação baixam arquivos de código-fonte público, que são lidos como texto e
analisados pelo Tree-sitter, sem nunca serem executados.

Refazer a coleta exige um token do GitHub com leitura de repositórios públicos
e, de preferência, uma chave da API do NVD. Nenhuma credencial está incluída
no repositório. Forneça-as por variável de ambiente ou pelo arquivo `.env`,
criado a partir de `.env.example`; o `.env` está no `.gitignore`. Não publique
saída de terminal que contenha os tokens.

Os arquivos de resultado nomeiam *forks* públicos em que a correção de uma CVE
não foi encontrada. Todas as CVEs envolvidas já são públicas e têm correção
publicada no projeto de origem. O veredito vulnerável é uma saída do método e
do revisor, sujeita a erro, e não uma confirmação de que o *fork* é explorável.

Alguns programas regravam os seus arquivos de saída na pasta da execução. Com
os dados incluídos o conteúdo regravado é idêntico. Para uma nova execução, use
sempre `--outdir` com uma pasta nova.

# Instalação

```bash
git clone https://github.com/robsonsants/Aardvark.git
cd Aardvark
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

A instalação está concluída quando o último comando termina sem erro. Para
refazer a coleta, copie `.env.example` para `.env` e preencha os dois tokens.

# Teste Mínimo

Roda sem rede, em menos de 5 segundos:

```bash
python -m py_compile src/pipeline_core.py src/pipeline_dissertation.py src/ground_truth.py src/experimento_regra_ab.py src/experimentos_revisores.py
python -c "import json; from pathlib import Path; r=Path('resultados/matrix/top10'); esperado={'dissertation_resultados.json':770,'dissertation_veredictos.json':460,'dissertation_cobertura.json':109}; obtido={n: len(json.loads((r/n).read_text(encoding='utf-8'))) for n in esperado}; assert obtido==esperado,(obtido,esperado); print('TESTE OK:',obtido)"
```

Saída esperada:

```text
TESTE OK: {'dissertation_resultados.json': 770, 'dissertation_veredictos.json': 460, 'dissertation_cobertura.json': 109}
```

# Experimentos

Há dois níveis de reprodução:

1. **Reprodução das análises.** Usa os dados incluídos para recalcular os
   resultados da dissertação. Roda sem rede e leva menos de um minuto no total.
2. **Nova coleta e nova verificação.** Consulta o NVD e o GitHub outra vez.
   Como as bases são vivas e a seleção de *forks* é dinâmica, o resultado
   difere da execução congelada. Métricas só são comparáveis quando saem da
   mesma coleta.

As reivindicações 1 e 2 descrevem a execução do método, as reivindicações 3 a
6 respondem à QP1 e as reivindicações 7 a 9 respondem à QP2. Nos comandos, a
execução oficial é `resultados/matrix/top10`.

## Reivindicação #1: Censo de vulnerabilidades do ecossistema

Dos 218 projetos do diretório, 160 foram lidos. O censo contém 127 CVEs
distintas em 24 projetos. A consulta ao NVD com guarda de atribuição aceitou 67
candidatas e rejeitou 408. A severidade está disponível para as 127 CVEs, com
17 baixas, 62 médias, 36 altas e 12 críticas; o CVSS numérico existe para 84 e
a categoria CWE para 94. Das 127, 72 têm *commit* de correção público, em 85
linhas de CVE e *commit* e 78 *commits* distintos.

```bash
python -c "import csv,collections as c; L=lambda f,d: list(csv.DictReader(open('dados/'+f,encoding='utf-8-sig'),delimiter=d)); e=L('cves_enriquecidas.csv',';'); f=L('cves-fixing-commits-dataset.csv',';'); n=L('censo_cpe_nvd.csv',';'); g=L('fase2_2026-09-18.csv',','); print('projetos lidos',len(g),'| com CVE no GHSA',sum(int(x['n_cves'] or 0)>0 for x in g)); print('NVD aceitas/rejeitadas',dict(c.Counter(x['aceito'] for x in n))); print('CVEs distintas',len({x['cve'] for x in e}),'| severidade',dict(c.Counter(x['severidade'] for x in e)),'| com CVSS',sum(bool(x['cvss']) for x in e),'| com CWE',sum(bool(x['cwes']) for x in e)); print('CVEs com commit',len({(x['github_repo'],x['id']) for x in f}),'| linhas',len(f),'| commits distintos',len({x['commit_sha'] for x in f}))"
```

A saída deve trazer 160 projetos lidos, 22 com CVE nos avisos do GitHub, 67
aceitas e 408 rejeitadas, 127 CVEs, 84 com CVSS, 94 com CWE, 72 CVEs com
*commit*, 85 linhas e 78 *commits* distintos. Os 24 projetos com CVE resultam
dos 22 dos avisos mais `olm` e `dendrite`, que só aparecem no NVD.

## Reivindicação #2: População verificada

A execução oficial verificou 64 das 72 CVEs com *commit* público, em 16
projetos e 109 *forks*, num total de 460 pares: 223 corrigidos, 7 vulneráveis,
103 na zona de incerteza e 127 com arquivo não encontrado, de modo que 333
pares são verificáveis. As oito CVEs excluídas têm causa nomeada: três em
linguagem sem analisador, quatro com correção fora do código-fonte e uma cujo
*commit* é um *merge* sem alteração própria.

```bash
python -c "import json,collections as c; R='resultados/matrix/top10/'; d=json.load(open(R+'dissertation_metricas.json')); v=json.load(open(R+'dissertation_veredictos.json',encoding='utf-8')); print({k:x for k,x in d.items() if k!='por_categoria'}); s=c.Counter(x['status'] for x in v); print(dict(s),'| verificaveis',len(v)-s['FILE_NOT_FOUND'])"
```

A saída deve trazer 16 projetos, 109 *forks*, 64 CVEs, 460 verificações,
cobertura média de 57,3% e 333 pares verificáveis. Os 7 vulneráveis aparecem
como 6 `VULNERAVEL`, decididos pela Camada 2B, e 1 `NAO_CORRIGIDO`, decidido
pela Camada 2A.

## Reivindicação #3: Desempenho contra o gabarito automático (QP1)

Nos 312 pares com rótulo automático conclusivo:

| Configuração | VP | FP | FN | VN | Precisão | Revocação | F1 | Kappa |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| União | 197 | 14 | 79 | 22 | 0,934 | 0,714 | 0,809 | 0,182 |
| A+B | 180 | 2 | 96 | 34 | 0,989 | 0,652 | 0,786 | 0,279 |
| Trivial, sempre corrigido | 276 | 36 | 0 | 0 | 0,885 | 1,000 | 0,939 | 0,000 |

```bash
python src/experimento_regra_ab.py --run resultados/matrix/top10
python -c "import json; d=json.load(open('resultados/matrix/top10_regraAB/gt_regra_ab_metricas.json')); b=d['base']; t={'TP':b['TP']+b['FN'],'FP':b['FP']+b['TN'],'FN':0,'TN':0}; k=lambda x:(lambda tp,fp,fn,tn,n:((tp+tn)/n-((tp+fp)*(tp+fn)+(fn+tn)*(fp+tn))/n**2)/(1-((tp+fp)*(tp+fn)+(fn+tn)*(fp+tn))/n**2))(x['TP'],x['FP'],x['FN'],x['TN'],x['TP']+x['FP']+x['FN']+x['TN']); [print(nome.ljust(8),x['TP'],x['FP'],x['FN'],x['TN'],'kappa %.3f'%k(x)) for nome,x in [('uniao',b),('A+B',d['regra_ab']),('trivial',t)]]"
```

O primeiro comando deriva a configuração A+B das mesmas linhas cruas, sem rede,
e regrava `resultados/matrix/top10_regraAB/` com
conteúdo idêntico. O segundo calcula o Kappa das três linhas.

## Reivindicação #4: Desempenho contra o gabarito humano (QP1)

A auditoria manual deu 311 corrigidos, 20 vulneráveis e 2 inconclusivos nos 333
pares. O gabarito automático concorda com ela em 289 pares, 86,8%. Nos 331
pares com veredito humano conclusivo:

| Classificador | VP | FP | FN | VN | Precisão | Revocação | F1 | Kappa |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Trivial, sempre corrigido | 311 | 20 | 0 | 0 | 0,940 | 1,000 | 0,969 | 0,000 |
| Camada 1 isolada | 28 | 0 | 283 | 20 | 1,000 | 0,090 | 0,165 | 0,012 |
| Camada 2A isolada | 175 | 16 | 136 | 4 | 0,916 | 0,563 | 0,697 | −0,062 |
| Camada 2B isolada | 146 | 0 | 165 | 20 | 1,000 | 0,469 | 0,639 | 0,097 |
| União | 208 | 13 | 103 | 7 | 0,941 | 0,669 | 0,782 | 0,006 |
| A+B | 187 | 2 | 124 | 18 | 0,989 | 0,601 | 0,748 | 0,130 |

O intervalo de confiança de 95% do Kappa da União é [−0,061; 0,078] e inclui
zero. A diferença entre União e A+B não é significativa no teste de McNemar,
com p = 0,11. Os 103 falsos negativos da União são todos pares na zona de
incerteza, ou seja, abstenções.

```bash
python src/experimentos_revisores.py --run resultados/matrix/top10
python src/auditoria_manual.py apurar --run resultados/matrix/top10
```

O primeiro comando leva cerca de 20 segundos, por causa das 10.000
reamostragens do *bootstrap*, e imprime os blocos E1 a E6: a tabela acima é o
E1, os intervalos e o McNemar são o E4, a validação cruzada é o E2 e a curva de
operação é o E6. A saída é determinística e igual a
`experimentos_revisores_log.txt`. Sob o gabarito automático este programa refaz
a decisão sem a tabela de prioridade da agregação e reporta a União com 195,
16, 79 e 22; os números oficiais contra o gabarito automático são os da
Reivindicação #3.

## Reivindicação #5: Sensibilidade e validação cruzada dos limiares (QP1)

Os limiares fixos não foram ajustados aos dados avaliados. Contra o gabarito
humano, a União com os limiares fixos tem Kappa 0,006. Na validação cruzada
que deixa um projeto de fora por vez e na validação em cinco partições, os
limiares escolhidos no treino (0,60 e margem 0,02) obtêm fora da amostra 256,
10, 55 e 10, com Kappa 0,157. Na curva de operação, o limiar superior da
Camada 2A em 0,50 dá Kappa 0,166 e em 0,95 dá 0,063. Limiares mais permissivos
reconhecem mais correções sem aumentar os falsos positivos.

```bash
python src/sensibilidade_regras.py --run resultados/matrix/top10
python src/experimentos_revisores.py --run resultados/matrix/top10
```

O primeiro comando imprime uma tabela por parâmetro e grava
`sensibilidade_limiares.json` na pasta da execução. Se usar `--outdir`, crie a
pasta antes. A validação cruzada é o bloco E2 e a curva de operação o E6 do
segundo comando.

## Reivindicação #6: Validação externa em Linux, FFmpeg e PHP (QP1)

Aplicado sem alteração aos ramos de manutenção do Linux, do FFmpeg e do PHP,
com as correções do conjunto de dados do PatchLens, o método avaliou 7.848
pares, dos quais 6.926 verificáveis, 88,7% deles de herança. Nos 649 pares em
que há propagação a decidir, a União obtém precisão 0,886, revocação 0,914, F1
0,900 e Kappa 0,389, e a A+B obtém precisão 0,969, revocação 0,867, F1 0,915 e
Kappa 0,618.

```bash
python -c "import json; d=json.load(open('resultados/validacao_externa/metricas_patchlens.json',encoding='utf-8')); t=d['populacao']['TOTAL']; print('pares',t['pares'],'| verificaveis',t['verificaveis'],'| heranca',t['proveniencia_verificaveis']['HERANCA']); [print(k.ljust(9),v) for k,v in d['metricas']['TOTAL']['proveniencia_refinada_sem_heranca'].items()]; [print(k.ljust(10),v['n'],v['taxa_resolvidos']) for k,v in d['verificabilidade_por_idade'].items()]"
```

A leitura por extenso está em
`resultados/validacao_externa/RESULTADOS_PATCHLENS.md`.
Recalcular desde a verificação exige os históricos Git completos dos três
projetos em uma pasta indicada pela variável `PATCHLENS_REPOS`, que não
acompanham o pacote, e o pacote `tree-sitter-c`. As fases são
`python src/experimento_patchlens.py oraculo`, `verificar` e `metricas`. Os
ramos de manutenção fazem o papel de *forks*, mas não são *forks*, e o
resultado é lido como generalização do comportamento do método.

## Reivindicação #7: Cobertura por categoria e recortes aninhados (QP2.1)

A cobertura média dos *forks* é de 57,3%: pontes 100,0%, suporte 93,3%,
integrações 75,0%, clientes 42,7%, servidores 41,6% e bibliotecas 39,1%. Os
recortes com 3, 5 e 10 *forks* por projeto saem da mesma coleta e são
aninhados.

```bash
python -c "import json; d=json.load(open('resultados/matrix/top10/dissertation_metricas.json')); print('media',d['cobertura_media_pct']); [print(k.ljust(12),v['n_verificacoes'],v['cobertura_media_pct']) for k,v in d['por_categoria'].items()]"
python src/recorte_topn.py --run resultados/matrix/top10 --top 3 --outdir recorte_top3_teste
```

O segundo comando deve reportar 16 projetos, 44 *forks*, 177 pares e
cobertura de 62,1%. A pasta `recorte_top3_teste` pode ser apagada.

## Reivindicação #8: Herança e propagação (QP2.1)

Dos 333 pares verificáveis, 274 (82,3%) são de herança: o *fork* foi criado
depois de todos os *commits* de correção da CVE e já nasceu corrigido. Outros
55 pares são de propagação e 4 não têm data. A auditoria classifica como
corrigidos os 274 pares de herança. Os 20 pares vulneráveis estão todos entre
os 55 de propagação, dos quais 35 estão corrigidos.

```bash
python -c "import json; d=json.load(open('resultados/matrix/top10/heranca_propagacao.json',encoding='utf-8')); print(d['top10']); print('metodo',d['status_por_classe']); print('humano',d['humano_por_classe'])"
```

A classificação compara a coluna `fork_created_at` com a coluna
`data_fix_upstream` de todos os *commits* de correção do par, em
`dataset_temporal_pares.csv`.

## Reivindicação #9: Tempo até a correção e fatores associados (QP2.2 e QP2.3)

Nos 34 pares de propagação corrigidos com data de adoção, o tempo até a
correção tem mediana de 48,7 dias, com primeiro quartil de 4,2 e terceiro de
384,9; 9 levaram mais de um ano. Os 20 pares vulneráveis estão expostos há
388,5 dias na mediana. Por CVE, com n = 36, a correlação entre CVSS e cobertura
é −0,078 e entre o ano de publicação e a cobertura é +0,535.

```bash
python -c "import json; d=json.load(open('resultados/matrix/top10/tempo_correcao.json',encoding='utf-8')); print(d['n_pares'],d['via']); print('corrigidos',d['corrigidos_com_data']); print('vulneraveis',d['vulneraveis_exposicao'])"
python src/enriquecer_cves.py --run resultados/matrix/top10 --saida cves_enriquecidas_teste.csv
```

O segundo comando imprime o perfil de severidade e de CWE e, ao final, as duas
correlações. O arquivo `cves_enriquecidas_teste.csv` pode ser apagado. O tempo
até a correção é um limite superior: a data de adoção é a do primeiro *commit*
próprio do *fork* que já contém a correção.

# Nova Coleta e Nova Verificação

Este procedimento consulta bases vivas, e os números não coincidirão com os da
execução congelada. Use sempre uma pasta de saída nova. Exporte as credenciais
sem imprimi-las:

```bash
export GITHUB_TOKEN='substitua-pelo-seu-token'
export NVD_TOKEN='substitua-pela-sua-chave'
```

**Fase 1, censo e commits de correção.** O passo 2 e a exportação precisam de
`--todas-linguagens`, senão o censo perde CVEs em silêncio.

```bash
python src/fase2_coletar.py dados/manifesto_ecossistema_matrix.csv --passo 1
python src/fase2_coletar.py dados/manifesto_ecossistema_matrix.csv --passo 2 --todas-linguagens
python src/fase2_coletar.py dados/manifesto_ecossistema_matrix.csv --passo 3
python src/fase2_coletar.py dados/manifesto_ecossistema_matrix.csv --exportar fase2_NOVO.csv --todas-linguagens
python src/censo_cpe_nvd.py --censo fase2_NOVO.csv --saida censo_cpe_nvd_NOVO.csv
python src/fase1_fix_commits.py --entrada fase2_NOVO.csv --saida fix_ghsa_NOVO.csv
python src/fase1_cves_do_nvd.py --entrada censo_cpe_nvd_NOVO.csv --saida fix_nvd_NOVO.csv
```

A guarda de atribuição do `censo_cpe_nvd.py` é obrigatória, porque a consulta
por nome de produto traz CVEs de produtos homônimos. Não use
`fase1_fix_commits.py --sem-nvd`: os avisos do GitHub sozinhos subcoletam.

**Fases 2 a 4, verificação.** Teste com um projeto antes de rodar todos.

```bash
python src/pipeline_dissertation.py --token "$GITHUB_TOKEN" --upstream matrix-org/sydent --top 3 --outdir resultados/NOVO
python src/pipeline_dissertation.py --token "$GITHUB_TOKEN" --fresh --top 10 --outdir resultados/NOVO
python src/recorte_topn.py --run resultados/NOVO --top 3 --outdir resultados/NOVO_top3
```

**Avaliação.**

```bash
python src/ground_truth.py --token "$GITHUB_TOKEN" --results resultados/NOVO/dissertation_resultados.json --outdir resultados/NOVO
python src/experimento_regra_ab.py --run resultados/NOVO
python src/sensibilidade_regras.py --run resultados/NOVO
python src/auditoria_manual.py gerar --run resultados/NOVO --cego --completo --revisor 1
python src/auditoria_manual.py apurar --run resultados/NOVO
python src/experimentos_revisores.py --run resultados/NOVO
```

A auditoria manual é o passo humano: `gerar` produz a lista de trabalho em
HTML, o revisor responde no navegador e exporta
`auditoria_manual_preenchida.csv` para a pasta da execução, e só então
`apurar` e `experimentos_revisores.py` podem rodar.

**Caracterização.**

```bash
python src/dataset_temporal.py --run resultados/NOVO
python src/tempo_correcao.py --run resultados/NOVO
python src/enriquecer_cves.py --censo fase2_NOVO.csv --cpe censo_cpe_nvd_NOVO.csv --run resultados/NOVO --saida cves_enriquecidas_NOVO.csv
unset GITHUB_TOKEN NVD_TOKEN
```

`tempo_correcao.py` clona os históricos dos projetos, sem os arquivos, na pasta
`repos_git/`, que não é versionada.

**Parâmetros do método**, fixos:

| Parâmetro | Valor |
|---|---|
| Limiar de corrigido da Camada 2A | similaridade ≥ 0,80 |
| Limiar de não corrigido da Camada 2A | similaridade ≤ 0,35 |
| Margem da zona de incerteza da Camada 2B | \|δ\| ≤ 0,05 |
| Piso de similaridade da guarda B | 0,60 |
| Similaridade combinada | 0,45 · Levenshtein + 0,55 · Zhang e Shasha |
| Limite de nós para Zhang e Shasha | 600 |
| Limiar de casamento de linha do gabarito automático | 0,85 |
| *Forks* por projeto | 3, 5 ou 10 |
| Janela de atividade dos *forks* | 730 dias |
| Máximo de *forks* comparados por projeto | 80 |

# Limitações Conhecidas

- **Revisor único.** Os resultados contra o gabarito humano usam os vereditos
  de um revisor, e a concordância entre avaliadores não foi medida.
- **Herança e propagação.** `heranca_propagacao.json` foi produzido em sessão
  de análise, sem programa próprio no pacote. A classificação pode ser refeita
  a partir de `dataset_temporal_pares.csv`, como descrito na Reivindicação #8.
- **Seleção de arquivo.** `select_patch_files` escolhe o arquivo pelo volume
  bruto de alteração e pode escolher um arquivo cuja mudança é só comentário.
  Isso ocorre na CVE-2026-45076 do `synapse` e produz os dois falsos positivos
  que restam na configuração A+B. O defeito foi mantido para que os resultados
  publicados continuem reproduzíveis.

# Licença

O código deste repositório é distribuído sob a Licença MIT (arquivo `LICENSE`).
O conjunto de dados em `dados/patchlens/` segue a licença do projeto PatchLens,
de origem.
