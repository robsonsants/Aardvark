# Dados

Entradas do método e coleta congelada em 18/09/2026. Os arquivos aparecem na
ordem em que são produzidos.

| Arquivo | Produzido por | Conteúdo |
|---|---|---|
| `manifesto_ecossistema_matrix.csv` | entrada | Os 218 projetos do diretório oficial do ecossistema Matrix, com camada, linguagem, maturidade, licença e a decisão de inclusão no estudo. |
| `fase2_2026-09-18.csv` | `src/fase2_coletar.py` | Censo dos 160 repositórios lidos: linguagem, *forks*, estrelas, último *push*, CVEs, severidade máxima e *forks* ativos e divergentes. |
| `censo_cpe_nvd.csv` | `src/censo_cpe_nvd.py` | CVEs candidatas do NVD por nome de produto, com a decisão da guarda de atribuição (67 aceitas, 408 rejeitadas). |
| `cves_enriquecidas.csv` | `src/enriquecer_cves.py` | As 127 CVEs do censo, com ano, CVSS, severidade e CWE. |
| `cves-fixing-commits-dataset.csv` | `src/fase1_fix_commits.py`, `src/fase1_cves_do_nvd.py` | Os *commits* de correção públicos (72 CVEs, 78 *commits*). É a entrada da verificação. |
| `target_dissertation.csv` | seleção | Os projetos *upstream* verificados, com a coluna `motivo` para os excluídos. |
| `cache_fase2/` | `src/fase2_coletar.py` | Respostas da API do GitHub, um arquivo por repositório. |
| `cache_cpe_nvd/` | `src/censo_cpe_nvd.py` | Respostas da API do NVD, um arquivo por produto. |
| `patchlens/final_dataset.csv` | PatchLens | Correções do Linux, do FFmpeg e do PHP usadas na validação externa. |

Os caches permitem refazer o censo e o enriquecimento sem rede.
