"""QP2.1 e QP2.3 pelo gabarito humano (offline, segundos).

A cobertura calculada pelos vereditos do método conta a zona de incerteza e o arquivo não
encontrado como não corrigido, e por isso mistura a propagação com a capacidade de decisão
do método. A dissertação caracteriza a propagação pelo veredito humano de cada par:

- QP2.1: presença da correção nos pares verificáveis e média por fork em cada categoria;
- QP2.3: correlação de Pearson entre a presença e a severidade (CVSS) e o ano da CVE, por
  CVE, e os commits à frente e atrás do upstream, por fork.

    python src/qp2_gabarito_humano.py --run resultados/matrix/top10 --cves dados/cves_enriquecidas.csv
"""
import argparse
import collections
import csv
import math
import statistics
from pathlib import Path

CATEGORIAS = {'bridge': 'ponte', 'server': 'servidor', 'client': 'cliente', 'support': 'suporte',
              'integration': 'integração', 'sdk': 'biblioteca'}


def pearson(xs, ys):
    mx, my = statistics.mean(xs), statistics.mean(ys)
    num = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    return num / math.sqrt(sum((a - mx) ** 2 for a in xs) * sum((b - my) ** 2 for b in ys))


def postos(v):
    ordem = sorted(range(len(v)), key=lambda i: v[i])
    r = [0.0] * len(v)
    i = 0
    while i < len(ordem):
        j = i
        while j + 1 < len(ordem) and v[ordem[j + 1]] == v[ordem[i]]:
            j += 1
        for k in range(i, j + 1):
            r[ordem[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def ler(caminho):
    return list(csv.DictReader(open(caminho, encoding='utf-8-sig'), delimiter=';'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', default='resultados/matrix/top10')
    ap.add_argument('--cves', default='dados/cves_enriquecidas.csv')
    a = ap.parse_args()
    run = Path(a.run)

    hum = [h for h in ler(run / 'auditoria_manual_preenchida.csv')
           if h['veredito_humano'] in ('CORRIGIDO', 'VULNERAVEL')]
    forks = {f['fork']: f for f in ler(run / 'dataset_temporal_forks.csv')}
    cves = {c['cve']: c for c in ler(a.cves)}

    # QP2.1: presença nos pares e média por fork em cada categoria
    tot = collections.Counter(h['veredito_humano'] for h in hum)
    n = sum(tot.values())
    print(f'QP2.1 presença: {tot["CORRIGIDO"]} de {n} pares ({100 * tot["CORRIGIDO"] / n:.1f}%)')
    por_fork = collections.defaultdict(collections.Counter)
    categoria = {}
    for h in hum:
        por_fork[h['fork']][h['veredito_humano']] += 1
        categoria[h['fork']] = h['categoria']
    pres = {f: 100 * c['CORRIGIDO'] / sum(c.values()) for f, c in por_fork.items()}
    print(f'  média por fork: {statistics.mean(pres.values()):.1f}% ({len(pres)} forks)')
    por_cat = collections.defaultdict(list)
    for f, v in pres.items():
        por_cat[categoria[f]].append(v)
    for cat, v in sorted(por_cat.items(), key=lambda x: -statistics.mean(x[1])):
        print(f'  {CATEGORIAS.get(cat, cat):<11} {len(v):>3} forks  {statistics.mean(v):5.1f}%')

    # QP2.3, por CVE: severidade e ano
    por_cve = collections.defaultdict(collections.Counter)
    for h in hum:
        por_cve[h['cve']][h['veredito_humano']] += 1
    sev, ano, ys = [], [], []
    for cve, c in por_cve.items():
        cvss = (cves.get(cve) or {}).get('cvss')
        if cvss:
            sev.append(float(cvss))
            ano.append(int(cve.split('-')[1]))
            ys.append(100 * c['CORRIGIDO'] / sum(c.values()))
    print(f'\nQP2.3 por CVE (n = {len(ys)}): CVSS r = {pearson(sev, ys):+.3f} | ano r = {pearson(ano, ys):+.3f}')

    # QP2.3, por fork: commits à frente e atrás do upstream
    for campo, nome in (('ahead_by', 'à frente'), ('behind_by', 'atrás')):
        xs, zs = [], []
        for f, v in pres.items():
            if f in forks and forks[f][campo]:
                xs.append(float(forks[f][campo]))
                zs.append(v)
        print(f'QP2.3 por fork (n = {len(xs)}): commits {nome:<8} r = {pearson(xs, zs):+.3f} '
              f'| Spearman {pearson(postos(xs), postos(zs)):+.3f}')
    com_vuln = [float(forks[f]['behind_by']) for f, v in pres.items()
                if v < 100 and f in forks and forks[f]['behind_by']]
    so_corr = [float(forks[f]['behind_by']) for f, v in pres.items()
               if v == 100 and f in forks and forks[f]['behind_by']]
    print(f'  commits atrás, mediana: forks com par vulnerável {statistics.median(com_vuln):.0f} '
          f'(n = {len(com_vuln)}) | só corrigidos {statistics.median(so_corr):.0f} (n = {len(so_corr)})')


if __name__ == '__main__':
    main()
