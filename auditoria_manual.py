#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditoria_manual.py - the human oracle: audit worklist and tally
==================================================================================
Builds the manual-audit worklist (HTML + CSV) and, once a reviewer has filled it in,
recomputes precision/recall/F1 against the HUMAN labels and the agreement between the
human and the automated ground truth.

WHY THIS STEP EXISTS
ground_truth.py is AUTOMATED: it measures the presence of the patch lines by textual
similarity. Evaluating the method against it measures the same kind of signal twice.
The independent oracle is human - and that is the protocol of the related work
(PatchLens: 500 cases, two reviewers; VERCATION: manual labelling).

HOW THE WORKLIST IS ORGANISED
Grouped by CVE, not by priority. The reviewer's cost is in understanding the flaw;
judging the forks afterwards is cheap. Each group opens with a CVE briefing (trigger,
effect, corrective anchor, where to look) followed by one card per failing pair.

DECLARED THREATS (carried into every document that uses these numbers)
  - single reviewer: there is no inter-rater agreement;
  - two complete passes, 3 verdicts revised on the second with a written justification;
  - few decisive cases (the A+B rule acts on 3 pairs).

Usage:
    python auditoria_manual.py gerar  --run resultados_2026-08-31_v2   # build worklist
    #  ... review in the browser, export auditoria_manual_preenchida.csv ...
    python auditoria_manual.py apurar --run resultados_2026-08-31_v2   # tally verdicts
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
        origem="proposta",
        gatilho="Decodificação base64 de chave de sessão Megolm vinda de fora.",
        efeito="O patch troca a implementação de base64 pela do crate `base64ct` "
               "(tempo constante) e passa a propagar o erro de decodificação.",
        anchor="base64ct::Base64Unpadded",
        procurar="Uso de `base64ct` no encode/decode da session key, e a variante de "
                 "erro `Base64(#[from] base64ct::Error)`."),
    "CVE-2024-40648": dict(
        origem="proposta",
        gatilho="Identidade própria usada como âncora de confiança sem estar ela "
                "mesma verificada e assinada.",
        efeito="Identidade de terceiro tratada como verificada indevidamente.",
        anchor="own_identity.is_verified() && own_identity.is_identity_signed",
        procurar="A condição dentro de `is_some_and(|own_identity| …)`. O fork pode ter "
                 "posto a mesma checagem em outro ponto da cadeia de verificação."),
    "CVE-2025-30355": dict(
        origem="proposta",
        gatilho="PDU recebida por federação com campo `depth` fora do intervalo "
                "canônico de inteiro.",
        efeito="Aceitação de evento malformado no processamento de federação.",
        anchor="filter_pdus_for_valid_depth",
        procurar="A filtragem por CANONICALJSON_MIN_INT / MAX_INT aplicada às pdus "
                 "antes do processamento."),
    "CVE-2025-53549": dict(
        origem="proposta",
        gatilho="NÃO CONSEGUI ISOLAR pelo diff — a mudança é uma reestruturação "
                "grande da consulta ao cache de eventos (+66/−43 linhas).",
        efeito="Indefinido a partir do diff. Vale ler o advisory antes de julgar.",
        anchor="collect_results",
        procurar="ESTE É O CASO QUE MERECE MAIS TEMPO: leia o advisory do GHSA antes "
                 "de decidir. O anchor sugerido é fraco."),
    "CVE-2025-62425": dict(
        origem="proposta",
        gatilho="NÃO DERIVÁVEL do diff: o único arquivo do fix commit que o pipeline "
                "reconhece é o de TESTE (crates/handlers/src/graphql/tests.rs).",
        efeito="A correção de produção está fora do escopo baixado. O veredito aqui se "
               "apoia na presença do teste de regressão.",
        anchor="(sem anchor de produção)",
        procurar="Verifique se o fork tem o teste de regressão do upstream. Para "
                 "julgar a correção em si seria preciso o commit completo."),
    "CVE-2026-45078": dict(
        origem="proposta",
        gatilho="Espera em lock de worker sem teto de retry nem timeout.",
        efeito="Espera indefinida sob contenção — exaustão de recurso.",
        anchor="_increment_timeout_interval",
        procurar="O tratamento `except defer.TimeoutError` e o incremento do intervalo. "
                 "NÃO use a constante WORKER_LOCK_MAX_RETRY_INTERVAL como anchor: ela "
                 "casa por similaridade com a versão pré-patch (seconds=60 × seconds=5) "
                 "e foi assim que o GT automático se enganou."),
}


# ─────────────────────────────────────────────────────────── carga
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
button.exp{font:12px/1 inherit;padding:7px 12px;border:1px solid var(--accent);
background:var(--panel);color:var(--accent);border-radius:6px;cursor:pointer;font-weight:600}
main{padding:20px 24px 80px;max-width:1180px;margin:0 auto}

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
const KEY='auditoria_%(run)s';
let dados = JSON.parse(localStorage.getItem(KEY) || '{}');
function salvar(){ localStorage.setItem(KEY, JSON.stringify(dados)); pintar(); }
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
}
function marcar(id,v){ dados[id]=Object.assign({},dados[id],{v:v}); salvar(); }
function sonda(id,b){ dados[id]=Object.assign({},dados[id],{sonda:b}); salvar(); }
function obs(id,t){ dados[id]=Object.assign({},dados[id],{obs:t}); localStorage.setItem(KEY,JSON.stringify(dados)); }
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
  const linhas=[['par_id','prioridade','cve','upstream','fork','categoria','gt_label',
                 'auto_uniao','auto_regra_ab','gatilho_ab','anchor','origem_ficha',
                 'veredito_humano','sonda_nao_corretiva','observacao']];
  document.querySelectorAll('.card').forEach(c=>{
    const d=dados[c.dataset.id]||{};
    linhas.push([c.dataset.id,c.dataset.p,c.dataset.cve,c.dataset.up,c.dataset.fork,
                 c.dataset.cat,c.dataset.gt,c.dataset.au,c.dataset.aab,c.dataset.gat,
                 c.dataset.anchor||'',c.dataset.origem||'',
                 d.v||'', d.sonda?'sim':'', (d.obs||'').replace(/;/g,',')]);
  });
  const csv='\\ufeff'+linhas.map(l=>l.join(';')).join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='auditoria_manual_preenchida.csv'; a.click();
}
document.addEventListener('DOMContentLoaded',pintar);
"""


def bloco_evidencia(e, rotulo):
    det = e.get("line_details") or []
    cls = "rotulo teste" if rotulo.startswith("teste") else "rotulo"
    out = ['<p class="%s">%s · %s</p>' % (cls, html.escape(rotulo),
                                          html.escape(e["filepath"]))]
    if not det:
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

    # ── CSV ────────────────────────────────────────────────────────────────
    with open(base / "auditoria_manual.csv", "w", newline="",
              encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["par_id", "prioridade", "cve", "upstream", "fork", "categoria",
                    "gt_label", "gt_confianca", "auto_uniao", "auto_regra_ab",
                    "gatilho_ab", "anchor", "origem_ficha", "link_fix_commit",
                    "link_arquivo_fork", "veredito_humano", "sonda_nao_corretiva",
                    "observacao"])
        for cve, ps in ordenados:
            fi = FICHAS.get(cve, {})
            for p in sorted(ps, key=lambda x: (ordem[x["prio"]], x["fork"])):
                e = p["evidencias"][0]
                w.writerow([
                    "%s::%s" % (p["fork"], p["cve"]), p["prio"], p["cve"],
                    p["upstream"], p["fork"], p["categoria"], p["gt_label"],
                    p["gt_conf"], p["auto_uniao"], p["auto_ab"],
                    "sim" if p["gatilho"] else "", fi.get("anchor", ""),
                    fi.get("origem", ""),
                    "https://github.com/%s/commit/%s" % (p["upstream"], e["fix_sha"]),
                    "https://github.com/%s/blob/HEAD/%s" % (p["fork"], e["filepath"]),
                    "", "", ""])

    # ── HTML ───────────────────────────────────────────────────────────────
    h = ['<!doctype html><html lang="pt-BR"><meta charset="utf-8">',
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
    for c, _t, _d in PRIORIDADES:
        if cont[c]:
            h.append('<button class="f" onclick="filtrar(\'%s\',this)">%s (%d)</button>'
                     % (c, c, cont[c]))
    h.append('<button class="exp" onclick="exportar()">exportar CSV</button>')
    h.append('</div></header><main>')
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
        ps = sorted(ps, key=lambda x: (ordem[x["prio"]], x["fork"]))
        fi = FICHAS.get(cve)
        up = ps[0]["upstream"]
        prios = sorted({p["prio"] for p in ps}, key=lambda x: ordem[x])
        h.append('<div class="grupo">')
        h.append('<div class="ficha"><div class="top">')
        h.append('<h2>%s</h2><span class="up">%s · %s · %d fork(s) · %s</span>'
                 % (cve, html.escape(up), ps[0]["categoria"], len(ps),
                    " ".join(prios)))
        if fi:
            if fi["origem"] == "gtv2":
                h.append('<span class="selo ok">anchor validado · auditoria de julho</span>')
            else:
                h.append('<span class="selo conf">ficha proposta · confirmar</span>')
        h.append('</div>')
        if fi:
            h.append('<dl>')
            h.append('<dt>Gatilho</dt><dd>%s</dd>' % html.escape(fi["gatilho"]))
            h.append('<dt>Efeito</dt><dd>%s</dd>' % html.escape(fi["efeito"]))
            h.append('<dt>Anchor</dt><dd><code>%s</code></dd>'
                     % html.escape(fi["anchor"]))
            h.append('<dt>Onde procurar</dt><dd>%s</dd>' % html.escape(fi["procurar"]))
            h.append('</dl>')
            termo = fi["anchor"].split("(")[0].strip()
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
                     % ("p1" if p["gatilho"] else "", html.escape(pid), p["prio"],
                        p["upstream"], p["categoria"], p["cve"],
                        html.escape(p["fork"]), p["gt_label"], p["auto_uniao"],
                        p["auto_ab"], "sim" if p["gatilho"] else "",
                        html.escape((fi or {}).get("anchor", "")),
                        (fi or {}).get("origem", "")))
            h.append('<div class="cab"><b>%s</b><span class="t-n">%s</span>'
                     % (html.escape(p["fork"]), p["prio"]))
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
    io.open(base / "auditoria_manual.html", "w", encoding="utf-8").write("".join(h))

    n_gtv2 = sum(1 for cve, _ in ordenados
                 if FICHAS.get(cve, {}).get("origem") == "gtv2")
    n_prop = sum(1 for cve, _ in ordenados
                 if FICHAS.get(cve, {}).get("origem") == "proposta")
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
    print("  HTML: %s" % (base / "auditoria_manual.html"))
    print("  CSV : %s" % (base / "auditoria_manual.csv"))


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
    args = ap.parse_args()
    base = Path(args.run)
    (gerar if args.acao == "gerar" else apurar)(base)


if __name__ == "__main__":
    main()
