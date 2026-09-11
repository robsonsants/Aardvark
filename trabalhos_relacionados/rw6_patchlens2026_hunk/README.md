# rw6 — PatchLens (Paixão et al., FSE 2026)

> Paixão, F. S., Santos, J. C. S., Silveira Neto, P. A. M., Menasché, D. S.,
> Figueiredo, G. B., Almeida, E. S. **Automated Detection of Configuration-Specific
> Security Vulnerabilities via Patch Analysis.** *Proc. ACM Softw. Eng.* 3, FSE,
> Article FSE119 (jul/2026), 23 p. DOI [10.1145/3808126](https://doi.org/10.1145/3808126)

## Por que este trabalho entra na comparação

O PatchLens é o trabalho mais recente que compartilha o **insumo** desta dissertação
(o patch de segurança) e a **técnica de base** (AST + mapeamento de hunks), mas ataca
um **espaço de derivados diferente**:

| | PatchLens (FSE 2026) | Esta dissertação |
|---|---|---|
| Pergunta | Quais **variantes de compilação** continham a falha? | Quais **forks divergentes** já receberam a correção? |
| Espaço de derivados | Configurações (`#ifdef`, Kconfig/Make) | Repositórios bifurcados (GitHub) |
| Como o derivado nasce | Seleção de opções em build-time | Cópia + divergência do histórico |
| Evidência | Condições de presença estáticas | Comparação de código entre repositórios |
| Saída | VIC: predicado booleano sobre opções | Veredito por (fork, CVE) + zona de incerteza |
| Linguagens | C/C++ não-preprocessado | Python, Rust, Kotlin, Swift, TypeScript, Go |

O *related work* do PatchLens é inteiramente sobre sistemas configuráveis
(TypeChef, SuperC, Kmax, PCLocator, SiB) — **propagação de patch em forks não
aparece**. Isso é evidência favorável: o nicho da dissertação continua distinto,
agora contra um FSE de 2026.

## O que este diretório **não** reproduz

A **Vulnerability Impact Condition (VIC)**. Ela exige (i) código não-preprocessado
com diretivas `#ifdef/#if/#elif` e (ii) análise do build system (Kbuild, Make,
Autotools) para derivar a condição de presença do arquivo. O ecossistema Matrix não
tem variabilidade em tempo de compilação: não há opções, não há condições de
presença, não há espaço de variantes. Calcular "VIC" aqui seria produzir um número
sem referente. **Não foi feito.**

## O que este diretório reproduz

O **mecanismo transferível** do PatchLens, descrito na Seção 3.2 do artigo:
mapear cada hunk do diff para a subárvore da AST que o contém ("maps each hunk to
its corresponding AST nodes by comparing these two trees") e raciocinar no escopo
dessa subárvore, unindo os hunks por **disjunção**.

Aplicado ao problema da dissertação, isso troca o escopo da Camada 2:

```
Camada 2 atual  : sim_AST( arquivo_do_fork , arquivo_pós_patch )
rw6 (PatchLens) : sim_AST( declaração_do_fork , declaração_pós_patch )
                  declaração = menor nó de função/método/classe que CONTÉM o hunk
```

A localização no fork é feita por `(tipo_do_nó, nome)`. Se a declaração alterada
pelo patch **não existe** no fork, a evidência não sustenta "corrigido" e o par vai
para a **zona de incerteza** — nunca para "seguro". Isso espelha a escolha do próprio
PatchLens de preferir super-aproximação a falso negativo ("the preferred failure
mode for security triage").

## Resultado (run `resultados_2026-08-17`, 78 pares com GT conclusivo)

| Escopo da comparação | TP | FP | FN | TN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| **arquivo** (pipeline atual) | 54 | 7 | 15 | 2 | 0,885 | 0,783 | 0,831 |
| **hunk** (PatchLens) | 60 | **3** | 9 | 6 | 0,952 | 0,870 | 0,909 |
| **hunk + Regra A** (δ ≥ 0) | 60 | **0** | 9 | 9 | **1,000** | **0,870** | **0,930** |

O escopo de hunk melhora **as duas** métricas ao mesmo tempo — não é troca de recall
por precisão. Elimina 5 dos 7 falsos positivos e ainda ganha 6 verdadeiros positivos.

**Os 5 FPs eliminados** são exatamente os casos de arquivo-monólito diagnosticados no
run 08-17: em `src/client.ts` (~10⁵ tokens) e `crates/…/user.rs`, o patch é pequeno
demais para mover a similaridade do arquivo inteiro. No escopo da declaração o sinal
reaparece.

**Os 3 FPs remanescentes** são todos `client.ts` do `matrix-js-sdk` com δ < 0
(similaridade 0,9924 contra o pós-patch, 1,0 contra o pré-patch): o fork é
*ligeiramente mais parecido com a versão vulnerável*. A "Regra A" (só aceitar 2A
como CORRIGIDO se δ ≥ 0) zera esses três sem custo de recall.

**Os 4 TPs perdidos** têm causa identificada e são informativos:
- 3 × `CVE-2024-52505` (`matrix-appservice-irc`): o hunk está no **topo do arquivo**
  (`Schema.ts`), fora de qualquer declaração. É a mesma classe de falha que o
  PatchLens reporta para o PHP (32% de insucesso) e para mudanças em headers.
- 1 × `CVE-2021-29432` (`sydent`): similaridade 0,601 na declaração — a 2B acerta
  (CORRIGIDO, δ > 0) mas a 2A sozinha não passa do limiar.

## Efeito colateral relevante para a metodologia

No escopo de **arquivo**, 116 das 125 comparações do run 08-17 usaram `lev_only`:
as árvores estouravam `ZSS_NODE_LIMIT = 600` e a distância Zhang-Shasha era
descartada. No escopo de **declaração** as subárvores cabem no limite e o ZSS volta a
compor a métrica (0,45×lev + 0,55×zss). Ou seja, o limite de 600 nós não era só uma
proteção de memória — estava decidindo *qual métrica* era aplicada em 93% dos casos.
Custo: ~30 s por comparação (o ZSS é O(n²)), contra ~1 s no escopo de arquivo.

## Corroboração de uma limitação da dissertação

Em *Threats to Validity*, o PatchLens registra que seu corpus vem apenas de
referências a commits do GitHub nos feeds do NVD, e que vulnerabilidades corrigidas
por outros canais — sem commit do GitHub — ficam de fora. É a mesma parede desta
dissertação: 30 das 72 CVEs do censo não têm fix commit nas referências do GHSA/NVD.
A limitação é do campo, não da implementação.

## Como rodar

```bash
# usa as evidências já em disco — não precisa de token nem rede
python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py --run resultados_2026-08-17

# só recalcula as métricas a partir do JSON gravado (segundos, não ~1 h)
python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py --refazer-metricas
```

Saída: `trabalhos_relacionados/resultados_AAAA-MM-DD/rw6_patchlens_hunk.json`.

## Ressalva

A "Regra A" foi desenhada olhando os próprios falsos positivos deste conjunto —
é **hipótese a validar em dados novos**, não melhoria validada. Já o escopo de hunk
(as linhas 1 e 2 da tabela) é a reprodução do mecanismo publicado, sem ajuste feito
sobre o resultado.
