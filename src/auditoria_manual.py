#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoria manual do ground truth — gerador da worklist e apurador dos vereditos.

POR QUE ESTA ETAPA EXISTE
O ground_truth.py e AUTOMATICO: mede a presenca das linhas do patch por
similaridade textual. Avaliar o metodo contra ele mede o mesmo tipo de sinal duas
vezes. O oraculo independente e humano — e e o protocolo dos trabalhos
relacionados (PatchLens: 500 casos, dois revisores; VERCATION: rotulagem manual).

COMO A WORKLIST E ORGANIZADA (v2)
Agrupada por CVE, nao por prioridade. O custo do revisor esta em entender a
falha; julgar os forks depois e barato. Sao 15 CVEs para ~41 pares, quase todas
com 3 forks: entende-se uma vez, aplica-se tres. A prioridade vira etiqueta no
card, e a ordem dos grupos segue a prioridade maxima da CVE.

Cada grupo abre com uma FICHA DA CVE (gatilho, efeito, anchor corretivo, onde
procurar). Os anchors das CVEs auditadas em julho vem do GT v2
(resultados_2026-07-04/VALIDACAO_GROUND_TRUTH.md); os demais sao PROPOSTA
derivada do diff e estao marcados como "a confirmar".

Uso:
    python auditoria_manual.py gerar  --run resultados/matrix/top10
    python auditoria_manual.py apurar --run resultados/matrix/top10
"""
import argparse
import csv
import html
import io
import json
import sys
from collections import defaultdict, Counter
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

PRIORIDADES = [
    ("P1", "Casos de gatilho da Regra A+B",
     "A regra recusou o CORRIGIDO aqui. São estes casos que sustentam a afirmação "
     "central — se o revisor discordar, ela cai."),
    ("P2", "Negativos do ground truth",
     "O GT diz VULNERÁVEL. Toda a precisão se apoia nestes."),
    ("P3", "Falsos negativos (GT corrigido, método na incerteza)",
     "O recall se apoia nestes."),
    ("P4", "Ambíguos (ficaram fora da métrica)",
     "O GT não concluiu. Um veredito humano aqui ACRESCENTA pares à avaliação."),
    ("P5", "Verdadeiros positivos por AST",
     "O grosso do conjunto. Amostrar já ajuda; não precisa ser censo."),
    ("P6", "Camada 1 (SHA bate)",
     "O fork contém o próprio commit de correção. Conferência formal."),
]

# ─────────────────────────────────────────────────────────── fichas por CVE
# origem="gtv2"   -> anchor validado na auditoria manual de julho (GT v2)
# origem="proposta" -> derivado por mim do diff pre/pos-patch; CONFIRME antes de usar
# origem="validada" -> proposta conferida em 25/09/2026: anchor presente nas linhas
#                      que o commit adiciona + efeito conferido contra o advisory
FICHAS = {
    # ---- anchors validados em julho (GT v2) ----------------------------------
    "CVE-2022-39252": dict(
        origem="gtv2",
        gatilho="Recebimento de um key forward vindo de outro usuário/dispositivo "
                "que não foi verificado.",
        efeito="Aceitação indevida da chave — bypass da verificação de identidade.",
        anchor="should_accept_forward",
        procurar="A função que decide aceitar o forward. Se o fork renomeou, procure "
                 "por qualquer checagem de 'é meu próprio device' antes de aceitar."),
    "CVE-2024-26131": dict(
        origem="gtv2",
        gatilho="Intent externa entregue à activity sem validação de origem.",
        efeito="Execução de componente não previsto (bypass de controle de acesso).",
        anchor="className in allowList",
        procurar="`fun Intent.isValid()` ou qualquer allowlist de className aplicada "
                 "antes de despachar a intent."),
    "CVE-2024-26132": dict(
        origem="gtv2",
        gatilho="Caminho de arquivo de mídia derivado de dado externo.",
        efeito="Escrita/leitura fora do diretório pretendido.",
        anchor='File(context.filesDir, "media")',
        procurar="A construção do diretório de mídia. O conserto ancora em filesDir; "
                 "o fork pode ter usado outro diretório interno igualmente seguro."),
    "CVE-2024-31208": dict(
        origem="gtv2",
        gatilho="Cadeia de eventos com muitos links, vinda de federação.",
        efeito="Explosão quadrática no cálculo — exaustão de recurso (DoS).",
        anchor="visited_chains",
        procurar="Travessia de grafo com conjunto de visitados, substituindo o "
                 "`get_links_from` O(n²). ATENÇÃO: correção ALGORÍTMICA — o fork pode "
                 "ter resolvido de outra forma, e aí o anchor não aparece."),
    "CVE-2024-34353": dict(
        origem="gtv2",
        gatilho="Regeneração da sessão Olm sem retomar o estado subsequente.",
        efeito="Estado inconsistente após rotação de chave.",
        anchor="setup_and_resume()",
        procurar="A ORDEM das chamadas: setup_and_resume depois de regenerate_olm. "
                 "É correção de ordenação — a presença do token não basta, confira a "
                 "sequência."),
    "CVE-2025-27606": dict(
        origem="gtv2",
        gatilho="Erro do servidor durante logout.",
        efeito="Sessão local mantida apesar da falha (bypass de logout).",
        anchor="ignoreLogoutServerError = true",
        procurar="A flag no fluxo de logout, ou equivalente que force a limpeza local."),
    "CVE-2025-48937": dict(
        origem="gtv2",
        gatilho="Evento cujo `sender` difere do user_id embutido no sender_data.",
        efeito="Atribuição incorreta de autoria — spoofing de remetente.",
        anchor="Some(i) if i != sender",
        procurar="A guarda que compara o user_id do sender_data com o sender do "
                 "evento."),
    "CVE-2025-61672": dict(
        origem="gtv2",
        gatilho="Corpo JSON malformado no upload de chaves.",
        efeito="Processamento de estrutura inválida.",
        anchor="validate_json_object(body, self.KeyUploadRequestBody)",
        procurar="Qualquer validação de esquema aplicada ao body ANTES do "
                 "processamento."),
    "CVE-2025-66622": dict(
        origem="gtv2",
        gatilho="Recebimento de um tipo de JoinRule não mapeado (custom).",
        efeito="Caminho não tratado no match — decisão de acesso indefinida.",
        anchor='warn!("Encountered a custom join rule")',
        procurar="O braço de fallback do `match` sobre join_rule. Se o fork tratou o "
                 "caso default de outro jeito (retornando negação segura), também vale."),
    # ---- propostas derivadas do diff — CONFIRMAR --------------------------------
    "CVE-2024-40640": dict(
        origem="validada",
        gatilho="Decodificação base64 de chave de sessão Megolm vinda de fora.",
        efeito="O patch troca a implementação de base64 pela do crate `base64ct` "
               "(tempo constante) e passa a propagar o erro de decodificação.",
        anchor="base64ct::Base64Unpadded",
        procurar="Uso de `base64ct` no encode/decode da session key, e a variante de "
                 "erro `Base64(#[from] base64ct::Error)`."),
    "CVE-2024-40648": dict(
        origem="validada",
        gatilho="Identidade própria usada como âncora de confiança sem estar ela "
                "mesma verificada e assinada.",
        efeito="Identidade de terceiro tratada como verificada indevidamente.",
        anchor="own_identity.is_verified() && own_identity.is_identity_signed",
        procurar="A condição dentro de `is_some_and(|own_identity| …)`. O fork pode ter "
                 "posto a mesma checagem em outro ponto da cadeia de verificação."),
    "CVE-2025-30355": dict(
        origem="validada",
        gatilho="PDU recebida por federação com campo `depth` fora do intervalo "
                "canônico de inteiro.",
        efeito="Aceitação de evento malformado no processamento de federação.",
        anchor="filter_pdus_for_valid_depth",
        procurar="A filtragem por CANONICALJSON_MIN_INT / MAX_INT aplicada às pdus "
                 "antes do processamento."),
    "CVE-2025-53549": dict(
        origem="validada",
        gatilho="Membro da sala envia evento com tipo de relação (`rel_type`) "
                "malicioso, consultado por `find_event_with_relations`.",
        efeito="Injeção de SQL no cache de eventos (SQLite).",
        anchor="repeat_vars(filters.len())",
        procurar="Em `crates/matrix-sdk-sqlite/src/event_cache_store.rs`: os filtros "
                 "entram como parâmetros (`rel_type IN ({question_marks})` + "
                 "`params_from_iter`), não mais formatados dentro da string SQL."),
    "CVE-2025-62425": dict(
        origem="validada",
        gatilho="Sessão autenticada no MAS pede operação sensível (trocar senha, "
                "e-mail) com a senha atual errada.",
        efeito="Operação aceita sem a senha atual — o resultado da verificação não "
               "era testado.",
        anchor=".is_success()",
        procurar="A correção está em `crates/handlers/src/graphql/mutations/mod.rs` e "
                 "`user.rs`: `res.is_success()` em vez de `res.is_ok()`. O card mostra "
                 "`graphql/tests.rs` (TESTE) — marque sonda não corretiva e julgue "
                 "pelos arquivos de mutations."),
    "CVE-2026-45078": dict(
        origem="validada",
        gatilho="Espera em lock de worker sem teto de retry nem timeout.",
        efeito="Espera indefinida sob contenção — exaustão de recurso.",
        anchor="_increment_timeout_interval",
        procurar="O tratamento `except defer.TimeoutError` e o incremento do intervalo. "
                 "NÃO use a constante WORKER_LOCK_MAX_RETRY_INTERVAL como anchor: ela "
                 "casa por similaridade com a versão pré-patch (seconds=60 × seconds=5) "
                 "e foi assim que o GT automático se enganou."),
}

# ---- fichas propostas em 25/09/2026 (run final72) --------------------------
# Derivadas do diff de cada commit de correcao; conferidas em 25/09 (anchor no
# diff + texto contra o advisory GHSA/NVD).
# Quando o arquivo do card NAO e onde a correcao mora, o "procurar" diz isso —
# nesses pares o revisor deve marcar "sonda nao corretiva".
def _F(gatilho, efeito, anchor, procurar):
    return dict(origem="validada", gatilho=gatilho, efeito=efeito,
                anchor=anchor, procurar=procurar)


FICHAS.update({
    # ---- synapse -----------------------------------------------------------
    "CVE-2018-10657": _F(
        "Evento recebido por federação com campo `depth` ausente, não inteiro, "
        "negativo ou enorme.",
        "Profundidade abusiva aceita — perturba a ordenação da sala (DoS).",
        "Depth too large",
        "Em `synapse/federation/federation_base.py`, `event_from_pdu_json`: exige "
        "`depth` e rejeita valor não inteiro, `< 0` ou `> MAX_DEPTH`."),
    "CVE-2020-26257": _F(
        "Requisição de federação cujo `room_id` do caminho difere do `room_id` do "
        "corpo do evento.",
        "Evento processado no contexto de outra sala — corrupção de estado / DoS.",
        'assert_params_in_dict(content, ["room_id"])',
        "A correção está em `synapse/federation/federation_server.py` (e "
        "`transport/server.py`): os handlers passam a usar `content[\"room_id\"]` "
        "do corpo, não o parâmetro de caminho. O arquivo do card é de TESTE e só "
        "remove um argumento — marque sonda não corretiva e julgue pelo servidor."),
    "CVE-2021-21273": _F(
        "Servidor de push ou URL de revogação de chave (convite de terceiros) "
        "apontando para IP interno.",
        "SSRF — o homeserver faz requisições para a rede interna.",
        "BlacklistingReactorWrapper",
        "Em `synapse/http/client.py`, a classe `BlacklistingReactorWrapper`, e o "
        "uso de `ip_range_blacklist` (não só `federation_ip_range_blacklist`) nos "
        "clientes HTTP de push e de verificação de chave."),
    "CVE-2021-21274": _F(
        "Servidor remoto responde a `/.well-known/matrix/server` com corpo enorme.",
        "Consumo ilimitado de memória — DoS.",
        "read_body_with_max_size",
        "`read_body_with_max_size` / `BodyExceededMaxSize` em "
        "`synapse/http/client.py` e o limite `WELL_KNOWN_MAX_SIZE` em "
        "`well_known_resolver.py`."),
    "CVE-2021-21332": _F(
        "Valor controlado pelo usuário renderizado em template HTML do servidor.",
        "XSS — o template não escapa HTML.",
        "jinja2.select_autoescape()",
        "Em `synapse/config/_base.py`, `read_templates` cria o `jinja2.Environment` "
        "com `autoescape=jinja2.select_autoescape()` (não mais `autoescape=False` "
        "por parâmetro)."),
    "CVE-2021-21333": _F(
        "Valor controlado pelo usuário renderizado em template HTML (e-mail / "
        "páginas de conta).",
        "XSS — o template não escapa HTML.",
        "jinja2.select_autoescape()",
        "Mesmo commit do CVE-2021-21332: `autoescape=jinja2.select_autoescape()` em "
        "`read_templates` (`synapse/config/_base.py`)."),
    "CVE-2021-29471": _F(
        "Regra de push com padrão glob cheio de curingas (`*?*?*...`).",
        "Regex com backtracking catastrófico — DoS no avaliador de push.",
        "_WILDCARD_RUN",
        "`glob_to_regex` em `synapse/util/__init__.py`: curingas consecutivos são "
        "colapsados (`_WILDCARD_RUN`, `.{n,}`). Implementação diferente que também "
        "simplifique os curingas conta como corrigido."),
    "CVE-2023-43796": _F(
        "Servidor remoto consulta por federação a lista de dispositivos de usuários "
        "que NÃO são deste homeserver.",
        "Vazamento de dispositivos de usuários remotos em cache — permite enumerar "
        "usuários conhecidos pelo servidor.",
        "User is not hosted on this homeserver",
        "Em `synapse/federation/federation_server.py`, a consulta de chaves recusa "
        "com 400 se algum `user_id` não for local (`self.hs.is_mine(...)`)."),
    "CVE-2026-45076": _F(
        "Página de `/messages` composta só de eventos rejeitados.",
        "Paginação termina cedo — histórico anterior fica oculto ao cliente.",
        "if not limited and not events",
        "A correção está em `synapse/handlers/pagination.py`: só encerra quando "
        "`not limited and not events`. Se o card mostrar `stream.py`, a mudança ali "
        "é SÓ docstring — marque sonda não corretiva e julgue pelo pagination.py."),
    # ---- sydent ------------------------------------------------------------
    "CVE-2019-11340": _F(
        "Endereço de e-mail malformado (ex.: com dois `@`).",
        "Contorna a restrição de registro por domínio (`allowed_local_3pids`): o "
        "endereço validado não é o que recebe o e-mail.",
        "smtp.sendmail(mailFrom, mailTo",
        "Em `sydent/util/emailutils.py`, `sendEmail` envia para o endereço CRU "
        "(`mailTo`), não para o resultado de `parseaddr` — e rejeita se o parse "
        "vier vazio."),
    "CVE-2021-29430": _F(
        "Corpo HTTP muito grande — requisição recebida ou resposta de homeserver "
        "(ex.: `.well-known`).",
        "Esgotamento de memória/disco — DoS.",
        "_ReadBodyWithMaxSizeProtocol",
        "`read_body_with_max_size` / `BodyExceededMaxSize` em "
        "`sydent/http/httpcommon.py`, usados por `matrixfederationagent.py`."),
    "CVE-2021-29431": _F(
        "Nome de servidor Matrix fornecido pelo cliente que resolve para IP "
        "interno.",
        "SSRF — o servidor de identidade acessa a rede interna.",
        "check_against_blacklist",
        "`sydent/http/blacklisting_reactor.py` (`BlacklistingReactorWrapper`, "
        "`check_against_blacklist`) e a validação `is_valid_matrix_server_name` em "
        "`sydent/util/stringutils.py`. São 4 commits; basta a filtragem de IP estar "
        "em uso nos clientes HTTP."),
    "CVE-2021-29432": _F(
        "Chamada a `store-invite` com `sender` diferente do usuário autenticado.",
        "E-mail de convite com remetente forjado.",
        "'sender' doesn't match",
        "Em `store_invite_servlet.py`: com auth, compara `account.userId` com "
        "`sender` e responde 403 se diferirem."),
    "CVE-2021-29433": _F(
        "`client_secret` ou endereço de e-mail arbitrariamente longo.",
        "Entrada sem limite de tamanho aceita pelo servidor de identidade.",
        "0 < len(client_secret) <= 255",
        "Em `sydent/util/stringutils.py`: limite de 255 no `client_secret` e "
        "`MAX_EMAIL_ADDRESS_LENGTH = 500`."),
    "CVE-2023-38686": _F(
        "Conexão SMTP com TLS para envio de e-mail.",
        "Certificado/hostname do servidor SMTP não verificados — MITM.",
        "ssl.create_default_context",
        "Em `sydent/util/emailutils.py`: `ctx = ssl.create_default_context(...)` e "
        "`context=ctx` em `SMTP_SSL(...)` e `starttls(...)`."),
    # ---- matrix-media-repo -------------------------------------------------
    "CVE-2021-29453": _F(
        "Imagem criada para ter dimensões enormes (bomba de descompressão).",
        "Esgotamento de memória ao gerar thumbnail — DoS.",
        "MaxPixels",
        "Em `thumbnailing/thumbnail.go`: `GetOriginDimensions` e recusa quando "
        "`w * h >= ...MaxPixels` (`ErrMediaTooLarge`)."),
    "CVE-2023-41318": _F(
        "Upload com `Content-Type` escolhido pelo usuário (ex.: `text/html`).",
        "Mídia servida inline no navegador — XSS.",
        'disposition = "attachment"',
        "Em `api/_routers/98-use-rcontext.go`: o tipo é detectado pelo conteúdo "
        "(`mimetype.DetectReader`) e o padrão vira `attachment`; `CanInline` em "
        "`util/mime.go` restringe o inline a uma lista segura."),
    # ---- dendrite ----------------------------------------------------------
    "CVE-2022-39200": _F(
        "Resposta de `/get_missing_events` com eventos de assinatura inválida.",
        "Eventos forjados aceitos na sala.",
        "VerifyEventSignatures",
        "Em `roomserver/internal/input/input_missing.go`: cada evento retornado "
        "passa por `ev.VerifyEventSignatures(ctx, t.keys)`; falhou, `continue`."),
    # ---- matrix-nio --------------------------------------------------------
    "CVE-2022-39254": _F(
        "Chave de sala encaminhada (forwarded room key) vinda de dispositivo não "
        "verificado ou de outro usuário.",
        "Aceitação da chave — personificação em salas cifradas.",
        "device.verified",
        "Em `nio/crypto/olm_machine.py`, `_should_accept_forward`: exige "
        "`device.verified` e `device.user_id == self.user_id`."),
    # ---- matrix-js-sdk -----------------------------------------------------
    "CVE-2021-40823": _F(
        "Pedido de reenvio de chave por um dispositivo cuja chave de identidade "
        "mudou.",
        "Chave Megolm reenviada a um dispositivo impostor.",
        "sessionSharedData.deviceKey !== device.getIdentityKey()",
        "Em `src/crypto/algorithms/megolm.ts`: `sharedWithDevices` guarda "
        "`deviceKey`, e o reshare recusa se a chave atual do dispositivo diferir."),
    "CVE-2022-39236": _F(
        "Evento de localização/beacon com conteúdo malformado.",
        "Beacon malformado interrompe o funcionamento do SDK (disponibilidade).",
        "if (!parsed.uri || !parsed.timestamp) return false",
        "A correção está em `src/models/beacon.ts` e `src/content-helpers.ts` "
        "(`location?.uri`). Commit compartilhado por 4 CVEs; se o card mostrar "
        "`megolm.ts` ou `crypto.spec.ts`, marque sonda não corretiva."),
    "CVE-2022-39249": _F(
        "Chave Megolm encaminhada por terceiro, sem ter sido pedida.",
        "Personificação — mensagens exibidas como de outro remetente.",
        "res.untrusted",
        "Em `src/crypto/algorithms/megolm.ts`: chave encaminhada vira `untrusted`; "
        "chave não pedida só é aceita se for shared history e vier de nós ou de "
        "quem convidou (`forwarded key not from inviter or from us`)."),
    "CVE-2022-39250": _F(
        "Verificação SAS em que o ID do dispositivo coincide com o ID da chave "
        "cross-signing.",
        "Confusão chave/dispositivo — verifica a chave errada.",
        "Device ID is the same as the cross-signing ID",
        "A correção está em `src/crypto/verification/Base.ts`: rejeita quando "
        "`crossSignId === this.deviceId` e grava a verificação com a chave "
        "(`keyId`). Se o card mostrar `megolm.ts`, marque sonda não corretiva."),
    "CVE-2022-39251": _F(
        "Evento `m.room_key` recebido por to-device sem cifra Olm.",
        "Chave aceita de remetente não autenticado — personificação.",
        "olmlib.isOlmEncrypted(event)",
        "Em `src/crypto/algorithms/megolm.ts`: `if (!olmlib.isOlmEncrypted(event))` "
        "rejeita, e confere que o dono da `senderKey` é o `sender` do evento."),
    "CVE-2024-42369": _F(
        "Salas cujos predecessores formam um ciclo.",
        "Laço infinito ao percorrer o histórico de upgrades — DoS no cliente.",
        "seenRoomIDs",
        "Em `src/client.ts` (histórico de upgrade de sala): conjunto "
        "`seenRoomIDs`; se o predecessor já foi visto, `break`."),
    "CVE-2024-47080": _F(
        "Convite em espaço MSC3089 (árvore de arquivos) com compartilhamento de "
        "histórico.",
        "Chaves de descriptografia enviadas a convidados — vazamento de histórico.",
        "sendSharedHistoryKeys",
        "PATCH DE REMOÇÃO: a correção APAGA `sendSharedHistoryKeys` de "
        "`src/client.ts` e o 3º parâmetro de `tree.invite`. Corrigido = o método "
        "NÃO existe mais (ou não é chamado no convite)."),
    "CVE-2025-59160": _F(
        "Sala que alega substituir outra sem que a antecessora aponte de volta.",
        "Sala legítima escondida da lista — spoofing de upgrade.",
        "findPredecessorRooms(room, true",
        "Em `src/client.ts`, `getVisibleRooms`: usa "
        "`findPredecessorRooms(room, true, ...)` (exige reciprocidade) e "
        "`getRoomUpgradeHistory(roomId, true)`."),
    # ---- appservice-bridge -------------------------------------------------
    "CVE-2021-32659": _F(
        "Sala nova que declara (tombstone) substituir uma sala ponteada.",
        "A ponte migra o bridging para sala do atacante.",
        "predecessor.room_id !== oldRoomId",
        "Em `src/components/room-upgrade-handler.ts`: lê o `m.room.create` da sala "
        "nova e recusa se `predecessor.room_id` não for a sala antiga."),
    "CVE-2023-38691": _F(
        "Token OpenID cujo MXID pertence a outro homeserver.",
        "Personificação na API de provisionamento.",
        "serverName !== server",
        "Em `src/provisioning/api.ts`: extrai o servidor do MXID e lança "
        "`ApiError` se diferir do servidor consultado."),
    # ---- appservice-irc ----------------------------------------------------
    "CVE-2023-38690": _F(
        "Comando de admin com quebras de linha (ex.: no nome do canal) repassado "
        "ao IRC.",
        "Injeção de comandos IRC — a biblioteca `matrix-org-irc` < 2.1.0 não "
        "trata as quebras de linha.",
        '"matrix-org-irc": "^2.1.0"',
        "A correção é ATUALIZAÇÃO DE DEPENDÊNCIA: `package.json` com "
        "`matrix-org-irc` >= 2.1.0. O card (`BridgedClient.ts`, teste de "
        "`pooling`) não é a correção — marque sonda não corretiva e confira a "
        "versão no `package.json` do fork."),
    "CVE-2023-38700": _F(
        "Resposta (reply) Matrix a um evento de OUTRA sala.",
        "Conteúdo de sala privada vazado para o canal IRC.",
        "getCachedEvent(event.room_id",
        "Em `src/bridge/MatrixHandler.ts`: o cache de eventos passa a ser "
        "indexado por sala — `getCachedEvent(event.room_id, replyEventId)`."),
    "CVE-2024-32000": _F(
        "Resposta a uma mensagem enviada antes de o usuário entrar na sala.",
        "Conteúdo anterior à entrada vazado para o IRC.",
        "senderJoinTs > cachedEvent.timestamp",
        "Em `src/bridge/MatrixHandler.ts`: `memberJoinTs` registra a entrada; se "
        "`senderJoinTs > cachedEvent.timestamp`, não trata como reply."),
    "CVE-2024-39691": _F(
        "Evento de entrada com `origin_server_ts` forjado.",
        "Contorna a proteção do CVE-2024-32000.",
        "memberJoinTs.set",
        "Em `src/bridge/MatrixHandler.ts`: `memberJoinTs.set(..., Date.now())` — "
        "hora do bridge, NÃO `event.origin_server_ts`."),
    "CVE-2024-52505": _F(
        "Nome de canal com caracteres de controle via API de provisionamento.",
        "Injeção de comandos IRC.",
        "x00-\\x1F",
        "Em `src/provisioning/Schema.ts`: o padrão do nome de canal exclui "
        "`\\x00-\\x1F` (e `src/models/IrcRoom.ts`)."),
    "CVE-2025-27146": _F(
        "Tópico de sala Matrix com quebras de linha.",
        "Injeção de comandos IRC via TOPIC.",
        "sanitized_topic",
        "Em `src/irc/BridgedClient.ts`: `topic.replace(/\\n/g, \" | \")` e remoção "
        "de `\\r` antes de enviar `TOPIC`."),
    # ---- hookshot / mjolnir ------------------------------------------------
    "CVE-2023-43656": _F(
        "Função de transformação JavaScript em webhook genérico.",
        "Escape do sandbox `vm2` — execução remota de código.",
        "quickjs-emscripten",
        "Em `src/Connections/GenericHook.ts`: `vm2` substituído por "
        "`quickjs-emscripten`. Corrigido = não importa mais `vm2`."),
    "CVE-2025-23197": _F(
        "Instalação do GitHub App suspensa ou que falha ao carregar.",
        "Hookshot quebra ao reiniciar (checagem ausente) — DoS.",
        "suspended_at",
        "Em `src/github/GithubInstance.ts`: pula `install.suspended_at` e envolve "
        "`addInstallation` em try/catch."),
    "CVE-2025-24024": _F(
        "Comando enviado ao bot fora da sala de gerenciamento.",
        "Comandos de moderação aceitos de qualquer sala protegida.",
        "roomId !== this.managementRoomId",
        "Em `src/Mjolnir.ts`: comandos só são processados se o evento vier da sala "
        "de gerenciamento. ATENÇÃO: há 2 commits (um reverte o recurso de "
        "menções, outro o reintroduz com a guarda) — o que importa é a guarda "
        "valer antes do tratamento de comandos."),
    # ---- element-x-android / element-web -----------------------------------
    "CVE-2025-27599": _F(
        "Intent/deeplink de chamada com URL de host arbitrário.",
        "Carrega página do atacante com as permissões do Element Call (microfone e "
        "câmera).",
        "it.host in knownHosts",
        "Em `CallIntentDataParser.kt`: `?.takeIf { it.host in knownHosts }` "
        "também para as URLs embutidas no esquema customizado."),
    "CVE-2026-55850": _F(
        "Homeserver malicioso fornece HTML para a página inicial (EmbeddedPage).",
        "Injeção de HTML (a CSP bloqueia JavaScript, mas permite phishing).",
        "sanitizedHtmlNode",
        "Em `apps/web/src/components/structures/EmbeddedPage.tsx`: o conteúdo "
        "passa por `sanitizedHtmlNode(...)` (HtmlUtils) antes de renderizar. Se o "
        "card mostrar só `HtmlUtils.tsx`, a mudança ali é de assinatura."),
})
# termo de busca no GitHub quando o anchor nao serve como consulta
_BUSCA = {'CVE-2019-11340': 'smtp.sendmail',
 'CVE-2020-26257': 'assert_params_in_dict',
 'CVE-2021-21332': 'select_autoescape',
 'CVE-2021-21333': 'select_autoescape',
 'CVE-2021-29432': "doesn't match",
 'CVE-2021-29433': 'MAX_EMAIL_ADDRESS_LENGTH',
 'CVE-2021-32659': 'predecessor.room_id',
 'CVE-2021-40823': 'sessionSharedData.deviceKey',
 'CVE-2022-39236': 'parsed.timestamp',
 'CVE-2022-39250': 'cross-signing ID',
 'CVE-2022-39251': 'isOlmEncrypted',
 'CVE-2023-38686': 'create_default_context',
 'CVE-2023-38690': 'matrix-org-irc',
 'CVE-2023-38691': 'serverName',
 'CVE-2023-38700': 'getCachedEvent',
 'CVE-2023-41318': 'attachment',
 'CVE-2024-26132': 'filesDir',
 'CVE-2024-32000': 'senderJoinTs',
 'CVE-2024-52505': 'x1F',
 'CVE-2025-24024': 'managementRoomId',
 'CVE-2025-27599': 'knownHosts',
 'CVE-2025-48937': 'i != sender',
 'CVE-2025-59160': 'findPredecessorRooms',
 'CVE-2025-66622': 'Encountered a custom join rule',
 'CVE-2025-53549': 'repeat_vars',
 'CVE-2025-62425': 'is_success',
 'CVE-2026-45076': 'not limited and not events'}
for _c, _b in _BUSCA.items():
    FICHAS[_c]["busca"] = _b




# ─────────────────────────────────────────────────────────── carga
# Modo cego: oculta do revisor o rotulo automatico e os vereditos do pipeline.
# Sem isso, a concordancia entre avaliadores fica contaminada por ancoragem.
CEGO = False
REVISOR = ""
LOTE = None   # (indice, total, n_sobreposicao, n_exclusivos ou None)
CALIB_CVE = "CVE-2025-66622"   # 3 casos de calibracao (P1, P2, P5) — tem ficha validada
CALIB = set()
COMPLETO = False               # --completo: todos recebem o mesmo conjunto inteiro                  # par_ids de calibracao, preenchido em compor_lotes()


def compor_lotes(pares, n, sobrep, k_excl, ordem):
    """Bloco comum POR PRIORIDADE (nao alfabetico) + exclusivos limitados a k_excl.

    Comum: 3 de calibracao de CALIB_CVE, depois cotas de P1 (gatilho A+B), P2
    (negativos) e P5 (TP por AST, para o bloco parecer a populacao), completando com
    P3. No maximo 2 pares por CVE, preferindo CVEs com ficha. Determinístico.
    Exclusivos: restante em ordem de prioridade (ficha primeiro dentro da mesma
    prioridade), distribuido em rodizio; cada revisor recebe no maximo k_excl.
    """
    pid = lambda p: "%s::%s" % (p["fork"], p["cve"])
    chave = lambda p: (ordem[p["prio"]], p["cve"] not in FICHAS, p["cve"], p["fork"])
    comuns, por_cve = [], Counter()
    cal = [p for p in sorted(pares, key=chave) if p["cve"] == CALIB_CVE]
    for alvo in ("P1", "P2", "P5"):
        x = next((p for p in cal if p["prio"] == alvo), None)
        if x:
            comuns.append(x)
    CALIB.clear(); CALIB.update(pid(p) for p in comuns)
    por_cve[CALIB_CVE] = 99   # a CVE de calibracao nao recebe mais nada
    resto_s = max(sobrep - len(comuns), 0)
    cotas = [("P1", round(resto_s * .3)), ("P2", round(resto_s * .3)),
             ("P5", round(resto_s * .25)), ("P3", resto_s)]
    usados = set(CALIB)
    for prio, cota in cotas:
        for p in sorted(pares, key=chave):
            if len(comuns) >= sobrep or cota <= 0:
                break
            if p["prio"] == prio and pid(p) not in usados and por_cve[p["cve"]] < 2:
                comuns.append(p); usados.add(pid(p)); por_cve[p["cve"]] += 1
                cota -= 1
    resto = [p for p in sorted(pares, key=chave)
             if pid(p) not in usados and (COMPLETO or p["cve"] != CALIB_CVE)]
    if k_excl is not None:
        # exclusivos estratificados: sem isso o rodizio em ordem de prioridade entrega
        # so P1 (os casos mais dificeis, quase todos sem ficha)
        total = n * k_excl
        cotas = [("P1", round(total * .3)), ("P2", round(total * .3)),
                 ("P3", round(total * .2)), ("P5", round(total * .2))]
        esc, ids = [], set()
        for prio, cota in cotas:
            for p in resto:
                if cota <= 0:
                    break
                if p["prio"] == prio and pid(p) not in ids:
                    esc.append(p); ids.add(pid(p)); cota -= 1
        esc += [p for p in resto if pid(p) not in ids][:total - len(esc)]
        resto = sorted(esc, key=chave)
    fatias = [[] for _ in range(n)]
    for j, p in enumerate(resto):
        fatias[j % n].append(p)
    return {pid(p) for p in comuns}, [{pid(p) for p in f} for f in fatias]


def carregar(base: Path):
    def J(nome, pasta=None):
        return json.load(open((pasta or base) / nome, encoding="utf-8"))

    gt = J("gt_dissertation_resultados.json")
    ver = J("dissertation_veredictos.json")
    ab_dir = Path(str(base).rstrip("/\\") + "_regraAB")
    verab = J("dissertation_veredictos.json", ab_dir)
    dif = J("DIFERENCIAL_regra_ab.json", ab_dir)

    auto = {(v["fork"], v["cve_id"]): v for v in ver}
    autoab = {(v["fork"], v["cve_id"]): v["status"] for v in verab}
    gatilho = {(m["fork"], m["cve"]) for m in dif["linhas_alteradas"]}

    PRIO = {"CONFIRMED_PATCHED": 4, "CONFIRMED_VULNERABLE": 3,
            "AMBIGUOUS": 2, "INACESSIVEL": 1}
    por_par = defaultdict(list)
    for g in gt:
        por_par[(g["fork"], g["cve"])].append(g)

    pares = []
    for chave, linhas in por_par.items():
        melhor = max(linhas, key=lambda g: PRIO.get(g["gt_label"], 0))
        a = auto.get(chave, {})
        pares.append({
            "fork": chave[0], "cve": chave[1],
            "upstream": linhas[0]["upstream"], "categoria": linhas[0]["category"],
            "gt_label": melhor["gt_label"], "gt_conf": melhor.get("gt_confidence"),
            "auto_uniao": a.get("status", "—"), "auto_ab": autoab.get(chave, "—"),
            "gatilho": chave in gatilho,
            "evidencias": sorted(linhas, key=lambda g: -PRIO.get(g["gt_label"], 0)),
        })
    return pares


def prioridade(p):
    if p["gatilho"]:
        return "P1"
    if p["gt_label"] == "CONFIRMED_VULNERABLE":
        return "P2"
    if p["gt_label"] == "CONFIRMED_PATCHED" and p["auto_uniao"] != "CORRIGIDO":
        return "P3"
    if p["gt_label"] not in ("CONFIRMED_PATCHED", "CONFIRMED_VULNERABLE"):
        return "P4"
    if any(e["tipo"] == "L1_SHA" for e in p["evidencias"]):
        return "P6"
    return "P5"


def eh_teste(caminho: str) -> bool:
    c = caminho.lower()
    return ("/test" in c or c.startswith("test") or "/tests/" in c
            or "_test." in c or "test_" in c.rsplit("/", 1)[-1] or "spec." in c)


# ─────────────────────────────────────────────────────────── HTML
CSS = """
:root{--ground:#FCFCFB;--panel:#fff;--sunk:#F5F4F0;--ink:#0B0B0B;--ink2:#52514E;
--ink3:#8A8880;--hair:#E3E2DA;--accent:#2A6FD6;--good:#0A7F32;--crit:#C0362F;
--warn:#8A6D00;--ficha:#FFFDF5}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);
font:15px/1.55 "Segoe UI",system-ui,sans-serif}
header{position:sticky;top:0;z-index:10;background:var(--ground);
border-bottom:1px solid var(--hair);padding:14px 24px}
h1{font-size:18px;margin:0 0 4px}
.sub{font-size:13px;color:var(--ink2);margin:0}
.bar{height:6px;background:var(--sunk);border-radius:3px;margin:12px 0 8px;overflow:hidden}
.bar>i{display:block;height:100%;background:var(--good);width:0%}
.filtros{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;align-items:center}
button.f{font:12px/1 inherit;padding:7px 11px;border:1px solid var(--hair);
background:var(--panel);border-radius:999px;cursor:pointer;color:var(--ink2)}
button.f.on{background:var(--accent);color:#fff;border-color:var(--accent)}
button.exp,label.exp{display:inline-block;font:12px/1 inherit;padding:7px 12px;border:1px solid var(--accent);
background:var(--panel);color:var(--accent);border-radius:6px;cursor:pointer;font-weight:600}
main{padding:20px 24px 80px;max-width:1180px;margin:0 auto}
.salvar{margin:8px 0 0;padding:8px 12px;border-radius:6px;font-size:13px;line-height:1.45;
background:#EAF4EC;border:1px solid #BCDCC3;color:#1E4D2B}
.salvar.pend{background:#FFF1E0;border-color:#F2C58C;color:#6B3D00}
.salvar.erro{background:#FDE8E8;border-color:#F1B0B0;color:#7A1C1C}

/* ---- ficha da CVE ---- */
.ficha{background:var(--ficha);border:1px solid #EADFAE;margin:34px 0 6px;
padding:16px 18px}
.ficha .top{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:baseline;
margin-bottom:10px}
.ficha h2{font-size:16px;margin:0}
.ficha .up{font-size:12.5px;color:var(--ink3)}
.ficha dl{display:grid;grid-template-columns:118px 1fr;gap:6px 14px;margin:0;
font-size:13.5px}
.ficha dt{color:var(--ink3);font-size:11.5px;text-transform:uppercase;
letter-spacing:.06em;padding-top:2px}
.ficha dd{margin:0;color:var(--ink2)}
.ficha code{font:12.5px "Cascadia Mono",Consolas,monospace;background:#fff;
border:1px solid #EADFAE;padding:1px 5px;border-radius:3px;color:var(--ink)}
.selo{font-size:10.5px;padding:2px 8px;border-radius:999px;border:1px solid currentColor;
text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.selo.ok{color:var(--good)}.selo.conf{color:var(--crit)}
.buscas{margin-top:11px;font-size:13px;display:flex;gap:14px;flex-wrap:wrap}
.buscas a{color:var(--accent)}

.card{background:var(--panel);border:1px solid var(--hair);border-left:3px solid var(--hair);
margin:10px 0;padding:13px 16px}
.card.feito{border-left-color:var(--good);opacity:.6}
.card.p1{border-left-color:var(--crit)}
.card.p1.feito{border-left-color:var(--good)}
.cab{display:flex;flex-wrap:wrap;gap:9px 14px;align-items:baseline}
.cab b{font-size:15px}
.tag{font-size:11px;padding:2px 7px;border:1px solid currentColor;border-radius:999px;
text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.t-ok{color:var(--good)}.t-bad{color:var(--crit)}.t-mid{color:var(--warn)}
.t-n{color:var(--ink3)}
.linhas{margin:9px 0 0;font:12.5px/1.5 "Cascadia Mono",Consolas,monospace}
.linhas table{border-collapse:collapse;width:100%}
.linhas td{padding:3px 8px 3px 0;border-bottom:1px solid #F0EFEA;vertical-align:top}
.linhas .ok{color:var(--good)}.linhas .no{color:var(--crit)}
.linhas .m{color:var(--ink3)}
.rotulo{font-size:11px;color:var(--ink3);text-transform:uppercase;letter-spacing:.06em;
margin:11px 0 2px}
.rotulo.teste{color:var(--accent)}
.links{margin-top:10px;font-size:13px;display:flex;gap:14px;flex-wrap:wrap}
.links a{color:var(--accent)}
.resp{margin-top:11px;padding-top:10px;border-top:1px dashed var(--hair);
display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.resp button{font:13px/1 inherit;padding:8px 13px;border:1px solid var(--hair);
background:var(--panel);border-radius:6px;cursor:pointer}
.resp button.sel[data-v=CORRIGIDO]{background:var(--good);color:#fff;border-color:var(--good)}
.resp button.sel[data-v=VULNERAVEL]{background:var(--crit);color:#fff;border-color:var(--crit)}
.resp button.sel[data-v=INCONCLUSIVO]{background:var(--warn);color:#fff;border-color:var(--warn)}
.resp input[type=text]{flex:1;min-width:220px;font:13px inherit;padding:7px 9px;
border:1px solid var(--hair);border-radius:6px;background:var(--ground);color:var(--ink)}
label.sonda{font-size:12.5px;color:var(--ink2);display:flex;gap:6px;align-items:center}
.aviso{background:#FFF8E5;border:1px solid #F0DFA8;padding:12px 14px;font-size:13.5px;
margin:14px 0 0}
.oculto{display:none}
"""

JS = """
const KEY='auditoria_%(run)s'+(window.SUF||'');
let ARMAZ_OK = true;
function ler(k, padrao){ try { return JSON.parse(localStorage.getItem(k) || padrao); }
                         catch(e){ ARMAZ_OK=false; return JSON.parse(padrao); } }
function gravar(k, v){ try { localStorage.setItem(k, JSON.stringify(v)); }
                       catch(e){ ARMAZ_OK=false; } }
let dados = ler(KEY, '{}');
let exportado = ler(KEY+'_exportado', '{}');   // retrato do ultimo CSV exportado/importado
const chave = d => JSON.stringify([d.v||'', !!d.sonda, d.obs||'']);
function naoExportadas(){
  const ids = new Set(Object.keys(dados).concat(Object.keys(exportado)));
  let n=0; ids.forEach(id=>{ if(chave(dados[id]||{})!==chave(exportado[id]||{})) n++; });
  return n;
}
function avisoSalvar(){
  const el=document.getElementById('avisoSalvar'); if(!el) return;
  const n=naoExportadas();
  if(!ARMAZ_OK){
    el.className='salvar erro';
    el.innerHTML='<b>Este navegador não está guardando as respostas.</b> Exporte o CSV '+
      'agora e a cada poucos casos. Para continuar depois, use <b>importar CSV</b>.';
  } else if(n>0){
    el.className='salvar pend';
    el.innerHTML='<b>'+n+' resposta(s) ainda não exportada(s).</b> Elas estão só neste '+
      'navegador — clique em <b>exportar CSV</b> ao terminar a sessão.';
  } else {
    el.className='salvar';
    el.innerHTML='Tudo exportado. As respostas ficam guardadas <b>neste navegador</b>; '+
      'o CSV exportado é o seu backup (em outro computador, use <b>importar CSV</b>).';
  }
}
function salvar(){ gravar(KEY, dados); pintar(); }
function pintar(){
  let feitos=0, total=0;
  document.querySelectorAll('.card').forEach(c=>{
    total++;
    const id=c.dataset.id, d=dados[id]||{};
    c.querySelectorAll('.resp button').forEach(b=>
      b.classList.toggle('sel', d.v===b.dataset.v));
    const cx=c.querySelector('input[type=checkbox]'); if(cx) cx.checked=!!d.sonda;
    const tx=c.querySelector('input[type=text]'); if(tx && d.obs!==undefined) tx.value=d.obs;
    c.classList.toggle('feito', !!d.v);
    if(d.v) feitos++;
  });
  document.getElementById('prog').style.width=(100*feitos/total)+'%%';
  document.getElementById('cont').textContent=feitos+' de '+total+' pares revisados';
  avisoSalvar();
}
function marcar(id,v){ dados[id]=Object.assign({},dados[id],{v:v}); salvar(); }
function sonda(id,b){ dados[id]=Object.assign({},dados[id],{sonda:b}); salvar(); }
function obs(id,t){ dados[id]=Object.assign({},dados[id],{obs:t}); gravar(KEY,dados); avisoSalvar(); }
function filtrar(p,btn){
  document.querySelectorAll('button.f').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.grupo').forEach(g=>{
    let algum=false;
    g.querySelectorAll('.card').forEach(c=>{
      const mostra = (p==='TODOS') || (p==='PEND' ? !c.classList.contains('feito')
                                                  : c.dataset.p===p);
      c.classList.toggle('oculto', !mostra);
      if(mostra) algum=true;
    });
    g.classList.toggle('oculto', !algum);
  });
}
function exportar(){
  const CEGO=!!window.CEGO;
  const cab=['par_id','prioridade','cve','upstream','fork','categoria','gt_label',
             'auto_uniao','auto_regra_ab','gatilho_ab','anchor','origem_ficha',
             'veredito_humano','sonda_nao_corretiva','observacao'];
  const corta=a=>CEGO?a.filter((_,i)=>i<6||i>9):a;
  const linhas=[corta(cab)];
  document.querySelectorAll('.card').forEach(c=>{
    const d=dados[c.dataset.id]||{};
    linhas.push(corta([c.dataset.id,c.dataset.p,c.dataset.cve,c.dataset.up,c.dataset.fork,
                 c.dataset.cat,c.dataset.gt,c.dataset.au,c.dataset.aab,c.dataset.gat,
                 c.dataset.anchor||'',c.dataset.origem||'',
                 d.v||'', d.sonda?'sim':'', (d.obs||'').replace(/;/g,',')]));
  });
  const csv='\\ufeff'+linhas.map(l=>l.join(';')).join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='auditoria_manual_preenchida'+(window.SUF||'')+'.csv'; a.click();
  exportado = JSON.parse(JSON.stringify(dados)); gravar(KEY+'_exportado', exportado);
  avisoSalvar();
}
function importar(inp){
  const f=inp.files[0]; if(!f) return;
  const r=new FileReader();
  r.onload=()=>{
    const linhas=String(r.result).replace(/^\\ufeff/,'').split(/\\r?\\n/).filter(l=>l.trim());
    const cab=(linhas.shift()||'').split(';');
    const ix=n=>cab.indexOf(n);
    const iId=ix('par_id'), iV=ix('veredito_humano'), iS=ix('sonda_nao_corretiva'), iO=ix('observacao');
    if(iId<0||iV<0){ alert('Este arquivo não é um CSV exportado desta página.'); inp.value=''; return; }
    const ids=new Set(Array.from(document.querySelectorAll('.card')).map(c=>c.dataset.id));
    const novos={}; let n=0, fora=0;
    linhas.forEach(l=>{
      const c=l.split(';'); const id=c[iId];
      if(!ids.has(id)){ fora++; return; }
      const d={}; if(c[iV]) d.v=c[iV]; if(iS>=0 && c[iS]==='sim') d.sonda=true;
      if(iO>=0 && c[iO]) d.obs=c.slice(iO).join(';');
      if(d.v||d.sonda||d.obs){ novos[id]=d; n++; }
    });
    const ja=Object.keys(dados).filter(id=>chave(dados[id])!==chave({})).length;
    if(ja && !confirm('Importar '+n+' resposta(s) de "'+f.name+'"?\\n\\nAs respostas deste '+
        'navegador para esses mesmos pares serão substituídas pelas do arquivo.')){ inp.value=''; return; }
    Object.assign(dados, novos); gravar(KEY, dados);
    exportado = JSON.parse(JSON.stringify(dados)); gravar(KEY+'_exportado', exportado);
    pintar(); inp.value='';
    alert(n+' resposta(s) importada(s).'+(fora?' '+fora+' linha(s) de outra lista foram ignoradas.':''));
  };
  r.readAsText(f, 'utf-8');
}
window.addEventListener('beforeunload', e=>{
  if(naoExportadas()>0){ e.preventDefault(); e.returnValue=''; }
});
document.addEventListener('DOMContentLoaded',pintar);
"""


def bloco_evidencia(e, rotulo):
    det = e.get("line_details") or []
    cls = "rotulo teste" if rotulo.startswith("teste") else "rotulo"
    out = ['<p class="%s">%s · %s</p>' % (cls, html.escape(rotulo),
                                          html.escape(e["filepath"]))]
    if not det:
        if CEGO:
            out.append('<p class="linhas m">Sem linhas testadas para este arquivo.</p>')
        else:
            out.append('<p class="linhas m">Sem linhas testadas (%s).</p>'
                       % html.escape(e["gt_label"]))
        return "".join(out)
    tipo = "removidas" if e.get("is_removal_patch") else "adicionadas"
    out.append('<div class="linhas"><table>')
    out.append('<tr><td colspan="3" class="m">linhas %s pelo patch, testadas no HEAD '
               'do fork</td></tr>' % tipo)
    for d in det[:8]:
        marca = ('<span class="ok">presente</span>' if d["present_in_fork"]
                 else '<span class="no">ausente</span>')
        if d.get("match") and d["match"].strip() != d["line"].strip():
            casou = ('<td class="m">casou com: %s <b>(%.3f)</b></td>'
                     % (html.escape(d["match"][:64]), d.get("score", 0)))
        else:
            casou = '<td class="m">%.3f</td>' % d.get("score", 0)
        out.append('<tr><td>%s</td><td>%s</td>%s</tr>'
                   % (marca, html.escape(d["line"][:74]), casou))
    if len(det) > 8:
        out.append('<tr><td colspan="3" class="m">… e mais %d linhas</td></tr>'
                   % (len(det) - 8))
    out.append("</table></div>")
    return "".join(out)


def busca_url(repo, termo):
    from urllib.parse import quote
    return ("https://github.com/search?type=code&q=" +
            quote('repo:%s "%s"' % (repo, termo)))


def gerar(base: Path):
    pares = carregar(base)
    for p in pares:
        p["prio"] = prioridade(p)
    ordem = {c: i for i, (c, _, _) in enumerate(PRIORIDADES)}

    # agrupa por CVE; a ordem dos grupos segue a prioridade MAXIMA da CVE
    grupos = defaultdict(list)
    for p in pares:
        grupos[p["cve"]].append(p)
    ordenados = sorted(grupos.items(),
                       key=lambda kv: (min(ordem[p["prio"]] for p in kv[1]), kv[0]))
    cont = Counter(p["prio"] for p in pares)
    run = base.name
    if LOTE:
        i, n, sobrep, k_excl = LOTE
        comuns, fatias = compor_lotes(pares, n, sobrep, k_excl, ordem)
        if COMPLETO:
            # todos revisam o mesmo conjunto: bloco comum + TODAS as fatias
            meus = comuns.union(*fatias)
            comuns = set(meus)
        else:
            meus = comuns | fatias[i - 1]
        pares = [p for p in pares
                 if "%s::%s" % (p["fork"], p["cve"]) in meus]
        grupos = defaultdict(list)
        for p in pares:
            grupos[p["cve"]].append(p)
        # calibracao primeiro, depois grupos com pares comuns, depois o resto
        def _k(kv):
            ids = {"%s::%s" % (q["fork"], q["cve"]) for q in kv[1]}
            return (0 if ids & CALIB else 1 if ids & comuns else 2,
                    min(ordem[q["prio"]] for q in kv[1]), kv[0])
        ordenados = sorted(grupos.items(), key=_k)
        cont = Counter(p["prio"] for p in pares)
        print("  lote %d/%d: %d pares (%d em sobreposicao)"
              % (i, n, len(pares), len(comuns)))

    # ── CSV ────────────────────────────────────────────────────────────────
    sufixo = ("_%s" % REVISOR) if REVISOR else ""
    nome_csv = base / ("auditoria_manual%s.csv" % sufixo)
    COLS_OCULTAS = ["gt_label", "gt_confianca", "auto_uniao", "auto_regra_ab",
                    "gatilho_ab"]
    with open(nome_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        cab = ["par_id", "prioridade", "cve", "upstream", "fork", "categoria",
               "gt_label", "gt_confianca", "auto_uniao", "auto_regra_ab",
               "gatilho_ab", "anchor", "origem_ficha", "link_fix_commit",
               "link_arquivo_fork", "veredito_humano", "sonda_nao_corretiva",
               "observacao"]
        if CEGO:
            cab = [c for c in cab if c not in COLS_OCULTAS]
        w.writerow(cab)
        for cve, ps in ordenados:
            fi = FICHAS.get(cve, {})
            for p in sorted(ps, key=lambda x: (ordem[x["prio"]], x["fork"])):
                e = p["evidencias"][0]
                linha = [
                    "%s::%s" % (p["fork"], p["cve"]), p["prio"], p["cve"],
                    p["upstream"], p["fork"], p["categoria"], p["gt_label"],
                    p["gt_conf"], p["auto_uniao"], p["auto_ab"],
                    "sim" if p["gatilho"] else "", fi.get("anchor", ""),
                    fi.get("origem", ""),
                    "https://github.com/%s/commit/%s" % (p["upstream"], e["fix_sha"]),
                    "https://github.com/%s/blob/HEAD/%s" % (p["fork"], e["filepath"]),
                    "", "", ""]
                if CEGO:
                    linha = [v for i, v in enumerate(linha) if i not in (6, 7, 8, 9, 10)]
                w.writerow(linha)

    # ── HTML ───────────────────────────────────────────────────────────────
    h = ['<!doctype html><html lang="pt-BR"><meta charset="utf-8">',
         '<script>window.SUF=%s;window.CEGO=%s;</script>'
         % (json.dumps(sufixo), 'true' if CEGO else 'false'),
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         '<title>Auditoria manual do ground truth — %s</title>' % run,
         '<style>%s</style>' % CSS, '<header>',
         '<h1>Auditoria manual do ground truth — %s</h1>' % run,
         '<p class="sub">Agrupada por CVE: entenda a falha uma vez na ficha, depois '
         'julgue os forks em sequência. A pergunta é sempre <b>a mudança que de fato '
         'corrige a falha está presente neste fork?</b></p>',
         '<div class="bar"><i id="prog"></i></div>',
         '<div class="filtros"><span id="cont" class="sub" '
         'style="margin-right:10px"></span>',
         '<button class="f on" onclick="filtrar(\'TODOS\',this)">todos</button>',
         '<button class="f" onclick="filtrar(\'PEND\',this)">pendentes</button>']
    for c, _t, _d in ([] if CEGO else PRIORIDADES):
        if cont[c]:
            h.append('<button class="f" onclick="filtrar(\'%s\',this)">%s (%d)</button>'
                     % (c, c, cont[c]))
    h.append('<button class="exp" onclick="exportar()">exportar CSV</button>')
    h.append('<label class="exp">importar CSV<input type="file" accept=".csv,text/csv" '
             'style="display:none" onchange="importar(this)"></label>')
    h.append('</div><div id="avisoSalvar" class="salvar"></div></header><main>')
    if CEGO:
        h.append('<div class="aviso"><b>Como ler os cards.</b> As linhas marcadas '
                 '<code>presente</code>/<code>ausente</code> são medição bruta de '
                 'semelhança textual, não veredito. Uma linha pode estar ausente e a '
                 'correção existir escrita de outro jeito — e o contrário também. Se a '
                 'linha testada não for a parte que de fato corrige a falha, marque '
                 '<b>“sonda não corretiva”</b> além do veredito.</div>')
    else:
      h.append('<div class="aviso"><b>O que procurar.</b> O ground truth automático casa '
               'linhas por similaridade textual, e falha de dois jeitos: (1) testa linhas '
               'que não corrigem nada — <code>import</code>s, declarações de campo, '
               'contexto; (2) aceita como “presente” uma linha que casou com a versão '
               '<i>pré-patch</i> — foi o que aconteceu no <code>CVE-2026-45078</code>, '
               'onde <code>Duration(seconds=60)</code> casou com <code>seconds=5</code> a '
               '0,971. Quando encontrar isso, marque <b>“sonda não corretiva”</b> além do '
               'veredito. O <b>anchor</b> de cada ficha é o sinal confiável; as linhas do '
               'card são o que a máquina usou.</div>')

    for cve, ps in ordenados:
        ps = sorted(ps, key=lambda x: ("%s::%s" % (x["fork"], x["cve"]) not in CALIB,
                                       ordem[x["prio"]], x["fork"]))
        fi = FICHAS.get(cve)
        up = ps[0]["upstream"]
        prios = sorted({p["prio"] for p in ps}, key=lambda x: ordem[x])
        h.append('<div class="grupo">')
        h.append('<div class="ficha"><div class="top">')
        h.append('<h2>%s</h2><span class="up">%s · %s · %d fork(s) · %s</span>'
                 % (cve, html.escape(up), ps[0]["categoria"], len(ps),
                    "" if CEGO else " ".join(prios)))
        if fi and not CEGO:
            if fi["origem"] == "gtv2":
                h.append('<span class="selo ok">anchor validado · auditoria de julho</span>')
            else:
                h.append('<span class="selo ok">ficha validada · diff + advisory '
                         '(25/09)</span>')
        h.append('</div>')
        if fi:
            h.append('<dl>')
            h.append('<dt>Gatilho</dt><dd>%s</dd>' % html.escape(fi["gatilho"]))
            h.append('<dt>Efeito</dt><dd>%s</dd>' % html.escape(fi["efeito"]))
            h.append('<dt>Anchor</dt><dd><code>%s</code></dd>'
                     % html.escape(fi["anchor"]))
            h.append('<dt>Onde procurar</dt><dd>%s</dd>' % html.escape(fi["procurar"]))
            h.append('</dl>')
            termo = fi.get("busca") or fi["anchor"].split("(")[0].strip()
            if termo and not termo.startswith("("):
                h.append('<div class="buscas">')
                for p in ps:
                    h.append('<a href="%s" target="_blank" rel="noopener">buscar o '
                             'anchor em %s</a>'
                             % (busca_url(p["fork"], termo),
                                html.escape(p["fork"].split("/")[0])))
                h.append('</div>')
        else:
            h.append('<p class="sub">Sem ficha — derive a mecânica pelo commit de '
                     'correção antes de julgar.</p>')
        h.append('</div>')

        for p in ps:
            pid = "%s::%s" % (p["fork"], p["cve"])
            e = p["evidencias"][0]
            cls_gt = {"CONFIRMED_PATCHED": "t-ok",
                      "CONFIRMED_VULNERABLE": "t-bad"}.get(p["gt_label"], "t-mid")
            cls_au = "t-ok" if p["auto_uniao"] == "CORRIGIDO" else "t-mid"
            h.append('<div class="card %s" data-id="%s" data-p="%s" data-up="%s" '
                     'data-cat="%s" data-cve="%s" data-fork="%s" data-gt="%s" '
                     'data-au="%s" data-aab="%s" data-gat="%s" data-anchor="%s" '
                     'data-origem="%s">'
                     % ("" if CEGO else ("p1" if p["gatilho"] else ""),
                        html.escape(pid), "" if CEGO else p["prio"],
                        p["upstream"], p["categoria"], p["cve"],
                        html.escape(p["fork"]),
                        "" if CEGO else p["gt_label"],
                        "" if CEGO else p["auto_uniao"],
                        "" if CEGO else p["auto_ab"],
                        "" if CEGO else ("sim" if p["gatilho"] else ""),
                        html.escape((fi or {}).get("anchor", "")),
                        "" if CEGO else (fi or {}).get("origem", "")))
            h.append('<div class="cab"><b>%s</b><span class="t-n">%s</span>'
                     % (html.escape(p["fork"]), "" if CEGO else p["prio"]))
            if pid in CALIB:
                h.append('<span class="tag t-mid">CALIBRAÇÃO — faça estes 3 primeiro '
                         'e pare</span>')
            if not CEGO:
                h.append('<span class="tag %s">GT: %s%s</span>'
                         % (cls_gt, p["gt_label"].replace("CONFIRMED_", "").lower(),
                            "" if p["gt_conf"] is None
                            else " %d%%" % round(100 * p["gt_conf"])))
                h.append('<span class="tag %s">união: %s</span>'
                         % (cls_au, p["auto_uniao"].lower()))
                if p["auto_ab"] != p["auto_uniao"]:
                    h.append('<span class="tag t-bad">A+B recusou → %s</span>'
                             % p["auto_ab"].lower())
            h.append('</div>')

            prod = [x for x in p["evidencias"] if not eh_teste(x["filepath"])]
            test = [x for x in p["evidencias"] if eh_teste(x["filepath"])]
            for x in prod[:1]:
                h.append(bloco_evidencia(x, "produção"))
            for x in test[:1]:
                h.append(bloco_evidencia(
                    x, "teste de regressão do patch — evidência comportamental"))
            restantes = len(p["evidencias"]) - len(prod[:1]) - len(test[:1])
            if restantes > 0:
                h.append('<p class="linhas m">… e mais %d arquivo(s)/commit(s) neste '
                         'par</p>' % restantes)

            h.append('<div class="links">'
                     '<a href="https://github.com/%s/commit/%s" target="_blank" '
                     'rel="noopener">1 · commit de correção</a>'
                     '<a href="https://github.com/%s/blob/HEAD/%s" target="_blank" '
                     'rel="noopener">2 · arquivo no HEAD do fork</a>'
                     '<a href="https://github.com/%s/compare/HEAD...%s:%s:HEAD" '
                     'target="_blank" rel="noopener">3 · fork vs upstream</a></div>'
                     % (p["upstream"], e["fix_sha"], p["fork"], e["filepath"],
                        p["upstream"], p["fork"].split("/")[0],
                        p["fork"].split("/")[1]))
            h.append('<div class="resp">')
            for v, r in (("CORRIGIDO", "corrigido"), ("VULNERAVEL", "ainda vulnerável"),
                         ("INCONCLUSIVO", "não dá para dizer")):
                h.append('<button data-v="%s" onclick="marcar(\'%s\',\'%s\')">%s</button>'
                         % (v, html.escape(pid), v, r))
            h.append('<label class="sonda"><input type="checkbox" '
                     'onchange="sonda(\'%s\',this.checked)"> sonda não corretiva</label>'
                     % html.escape(pid))
            h.append('<input type="text" placeholder="observação (opcional)" '
                     'oninput="obs(\'%s\',this.value)"></div></div>'
                     % html.escape(pid))
        h.append('</div>')
    h.append('</main><script>%s</script></html>' % (JS % {"run": run}))
    nome_html = base / ("auditoria_manual%s.html" % sufixo)
    io.open(nome_html, "w", encoding="utf-8").write("".join(h))

    n_gtv2 = sum(1 for cve, _ in ordenados
                 if FICHAS.get(cve, {}).get("origem") == "gtv2")
    n_prop = sum(1 for cve, _ in ordenados
                 if FICHAS.get(cve, {}).get("origem") in ("proposta", "validada"))
    n_sem = len(ordenados) - n_gtv2 - n_prop
    print("Worklist gerada — %d pares em %d CVEs" % (len(pares), len(ordenados)))
    print()
    for c, titulo, _ in PRIORIDADES:
        if cont[c]:
            print("  %-3s %-52s %3d pares" % (c, titulo, cont[c]))
    print()
    print("  fichas com anchor validado em julho : %d CVEs" % n_gtv2)
    print("  fichas propostas (CONFIRMAR)        : %d CVEs" % n_prop)
    if n_sem:
        print("  CVEs sem ficha                      : %d" % n_sem)
    print()
    print("  HTML: %s" % nome_html)
    print("  CSV : %s" % nome_csv)


# ─────────────────────────────────────────────────────────── apuração
def apurar(base: Path):
    caminho = base / "auditoria_manual_preenchida.csv"
    if not caminho.exists():
        print("Nao encontrei %s" % caminho)
        print("Exporte o CSV pelo botao do HTML e salve com esse nome.")
        return
    linhas = list(csv.DictReader(open(caminho, encoding="utf-8-sig"), delimiter=";"))
    humano = {r["par_id"]: r for r in linhas if (r.get("veredito_humano") or "").strip()}
    print("Pares revisados: %d de %d" % (len(humano), len(linhas)))
    if not humano:
        return

    pares = {("%s::%s" % (p["fork"], p["cve"])): p for p in carregar(base)}

    conc = Counter()
    divergentes = []
    for pid, r in humano.items():
        p = pares.get(pid)
        if not p:
            continue
        gt = p["gt_label"]
        hv = r["veredito_humano"].strip().upper()
        equiv = {"CONFIRMED_PATCHED": "CORRIGIDO",
                 "CONFIRMED_VULNERABLE": "VULNERAVEL"}.get(gt, "INCONCLUSIVO")
        conc["concorda" if equiv == hv else "diverge"] += 1
        if equiv != hv:
            divergentes.append((pid, gt, hv, r.get("observacao", "")))
    print("\nGROUND TRUTH AUTOMATICO vs REVISOR")
    print("  concorda: %d   diverge: %d   (%.1f%% de concordancia)"
          % (conc["concorda"], conc["diverge"],
             100.0 * conc["concorda"] / max(1, sum(conc.values()))))
    sondas = sum(1 for r in humano.values()
                 if (r.get("sonda_nao_corretiva") or "").strip())
    print("  pares marcados com sonda nao corretiva: %d" % sondas)
    if divergentes:
        print("\n  divergencias:")
        for pid, gt, hv, obs in divergentes:
            print("    %-50s GT=%-22s humano=%-13s %s"
                  % (pid[:50], gt, hv, (obs or "")[:40]))

    n_conc = sum(1 for r in humano.values()
                 if r["veredito_humano"].strip().upper() in ("CORRIGIDO", "VULNERAVEL"))
    print("\nMETRICAS CONTRA O ROTULO HUMANO (%d pares conclusivos)" % n_conc)
    print("  %-10s %4s %3s %4s %3s  %-7s %-7s %-7s"
          % ("regra", "TP", "FP", "FN", "TN", "P", "R", "F1"))
    for nome, campo in (("uniao", "auto_uniao"), ("regra A+B", "auto_ab")):
        tp = fp = fn = tn = 0
        for pid, r in humano.items():
            hv = r["veredito_humano"].strip().upper()
            if hv not in ("CORRIGIDO", "VULNERAVEL"):
                continue
            p = pares.get(pid)
            if not p:
                continue
            a = p[campo] == "CORRIGIDO"
            real = hv == "CORRIGIDO"
            if a and real: tp += 1
            elif a:        fp += 1
            elif real:     fn += 1
            else:          tn += 1
        P = tp / (tp + fp) if tp + fp else None
        R = tp / (tp + fn) if tp + fn else None
        F = 2 * P * R / (P + R) if P and R else None
        print("  %-10s %4d %3d %4d %3d  %-7s %-7s %-7s"
              % (nome, tp, fp, fn, tn,
                 "—" if P is None else "%.4f" % P,
                 "—" if R is None else "%.4f" % R,
                 "—" if F is None else "%.4f" % F))

    saida = base / "auditoria_manual_apuracao.json"
    json.dump({"n_revisados": len(humano), "concordancia": dict(conc),
               "sondas_nao_corretivas": sondas,
               "divergencias": [{"par": d[0], "gt": d[1], "humano": d[2], "obs": d[3]}
                                for d in divergentes]},
              open(saida, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("\n-> %s" % saida)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("acao", choices=["gerar", "apurar"])
    ap.add_argument("--run", required=True)
    ap.add_argument("--cego", action="store_true",
                    help="oculta do revisor o rotulo automatico e os vereditos "
                         "do pipeline (obrigatorio para concordancia entre avaliadores)")
    ap.add_argument("--revisor", default="",
                    help="identificador do revisor; entra no nome dos arquivos")
    ap.add_argument("--lote", default="",
                    help="i/N[+S[xK]]: lote i de N revisores, S pares comuns a todos "
                         "(compostos por prioridade, 3 de calibracao) e ate K "
                         "exclusivos por revisor")
    ap.add_argument("--completo", action="store_true",
                    help="com --lote: todos os revisores recebem o MESMO conjunto "
                         "(bloco comum + todas as fatias); sobreposicao total")
    args = ap.parse_args()
    global CEGO, REVISOR, LOTE, COMPLETO
    COMPLETO = args.completo
    CEGO = args.cego
    REVISOR = "".join(ch for ch in args.revisor if ch.isalnum() or ch in "-_")
    if args.lote:
        corpo, _, s = args.lote.partition("+")
        s, _, k = s.partition("x")
        i, _, n = corpo.partition("/")
        LOTE = (int(i), int(n), int(s) if s else 0, int(k) if k else None)
    base = Path(args.run)
    (gerar if args.acao == "gerar" else apurar)(base)


if __name__ == "__main__":
    main()
