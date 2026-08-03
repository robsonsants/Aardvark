"""
pipeline1.py  —  Phase 1: mining vulnerabilities and their fix commits
==========================================================================
Starting from the CPE of each upstream product listed in target.csv, this script
mines the NVD and GHSA advisory databases and locates the commit that fixes each
CVE by scanning the advisory references.

Pipeline:
  target.csv -> CPEs (NVD) -> CVEs (NVD) -> GHSAs (GitHub) -> cross-mined CVEs
             -> fix commits (URLs of the form /commit/<sha40> in the references)

The NVD API (services.nvd.nist.gov) returns frequent 503/timeout errors, so every
request goes through exponential backoff (see with_retry below). This is a known
NIST service instability, not a fault of the input data.

Usage:
    python pipeline1.py NVD_TOKEN GITHUB_TOKEN

Outputs:
    cpe-nvd-dataset.csv              -- mined CPEs
    cve-nvd-dataset.csv              -- mined CVEs
    ghsa-dataset.csv                 -- mined GHSA advisories
    ghsa-cve-nvd-dataset.csv         -- CVEs reached through GHSA
    cves-fixing-commits-dataset.csv  -- fix commits (this is the Phase 2 input)

Note: 7 of the 16 CVEs in the final study are NOT recoverable by this script because
their advisories do not reference the commit; those were located manually and are
documented in ANEXO_DIAGNOSTICO_C5_C6_C8.md.
"""

import nvdlib
import re
import time
import pandas
import requests
import logging
import numpy
import sys
from urllib.parse import urlparse

# Windows: forçar UTF-8 no console (evita UnicodeEncodeError em prints/logs).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

logger = logging.getLogger(__name__)

# ─── Retry / Backoff para instabilidade crônica da NVD API ──────────────────
# A API do NVD (services.nvd.nist.gov) sofre com erros 503/timeout frequentes,
# documentados publicamente desde 2024. Isso não é um problema do nosso código
# ou do target.csv — e instabilidade do servico do NIST. A solucao e tentar
# novamente com espera exponencial antes de desistir.
MAX_RETRIES   = 6
BASE_DELAY    = 5     # segundos, dobra a cada tentativa: 5, 10, 20, 40, 80, 160
MAX_DELAY     = 180   # nunca espera mais que 3 minutos entre tentativas


def with_retry(func, *args, what="operacao", **kwargs):
    """
    Executa func(*args, **kwargs) com retry exponencial.
    Trata especificamente os erros transitorios mais comuns do NVD/GitHub:
    503 Service Unavailable, timeouts de leitura, e erros de conexao.
    Retorna o resultado de func, ou None se todas as tentativas falharem.
    """
    delay = BASE_DELAY
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except Exception as error:
            last_error = error
            msg = str(error)
            transient = any(code in msg for code in
                            ["503", "502", "504", "timeout", "Timeout",
                             "ConnectionError", "Read timed out"])
            if not transient:
                # Erro nao-transitorio (ex: CPE malformado): nao vale retry.
                logger.debug(f"Erro nao-transitorio em {what}, abortando retry: {error}")
                raise
            logger.warning(
                f"[retry {attempt}/{MAX_RETRIES}] Falha transitoria em {what}: {error}. "
                f"Aguardando {delay}s antes de tentar novamente."
            )
            if attempt < MAX_RETRIES:
                time.sleep(delay)
                delay = min(delay * 2, MAX_DELAY)
    logger.error(f"Todas as {MAX_RETRIES} tentativas falharam para {what}: {last_error}")
    return None


#########################################
#[Step-1] Mining CPEs from NVD Database #
#########################################

def load_target_projects():
    """
    Loads and return a DataFrame containing all target projects stored in a .csv file.
    """
    return pandas.read_csv("target.csv",
                           index_col=None, 
                           header=0, 
                           delimiter=';')

def retrieve_target_cpe_wfn_patterns():
    dataset = load_target_projects()
    return list(set(dataset["cpe_wfn_pattern"].to_list()))

def load_cpe_nvd_dataset():
    """
    Loads and return a DataFrame containing  all CPEs stored in a .csv file dataset.
    """
    dataset = pandas.read_csv("cpe-nvd-dataset.csv",
                              index_col=None,
                              header=0, 
                              delimiter=';', 
                              dtype={"version":"string"}, 
                              parse_dates=['creation_date', 'last_midication_date'])
    return dataset.replace({numpy.nan: None})

def save_cpe_nvd_dataset(dataset):
    """
    Stores a DataFrame containing  all mined CPEs into a .csv file dataset.
    """
    dataset.to_csv("cpe-nvd-dataset.csv", 
                   sep=';', 
                   encoding='utf-8', 
                   index=False)

def parse_cpe_uri_2_3(cpe_string):
    """
    Parses a CPE 2.3 string and returns a dictionary with the components.
    """
    # Define the pattern for CPE 2.3 strings
    pattern = r'cpe:2\.3:([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)'
    
    match = re.match(pattern, cpe_string)
    
    if not match:
        raise ValueError("Invalid CPE 2.3 string")
    
    components = {
        "part": match.group(1),
        "vendor": match.group(2),
        "product": match.group(3),
        "version": match.group(4),
        "update": match.group(5),
        "edition": match.group(6),
        "language": match.group(7),
        "sw_edition": match.group(8),
        "target_sw": match.group(9),
        "target_hw": match.group(10),
        "other": match.group(11)
    }
    
    return components

def process_cpe(cpe):
    """
    Process a CPE 2.3 extracting all interested information and returns a dictionary with the information.
    """    
    if cpe is not None:
        cpe_data = {}
        cpe_data["cpe_uuid"] = cpe.cpeNameId
        cpe_data["cpe_uri"] = cpe.cpeName
        cpe_data["creation_date"] = cpe.created
        cpe_data["last_midication_date"] = cpe.lastModified
        cpe_data["deprecated"] = cpe.deprecated
        if hasattr(cpe, 'deprecatedBy'):
            cpe_data["deprecated_by"] = cpe.deprecatedBy
        else:
            cpe_data["deprecated_by"] = None
        
        components = {}
        try:
           components = parse_cpe_uri_2_3(cpe.cpeName)
        except ValueError as error:
            print("Error in parsing CPE name {}: \n {}".format(cpe.cpeName, error))

        cpe_data["part"] = components.get("part")
        cpe_data["vendor"] = components.get("vendor")
        cpe_data["product"] = components.get("product")
        cpe_data["version"] = components.get("version")
        cpe_data["update"] = components.get("update")
        cpe_data["edition"] = components.get("edition")
        cpe_data["language"] = components.get("language")
        cpe_data["sw_edition"] = components.get("sw_edition")
        cpe_data["target_sw"] = components.get("target_sw")
        cpe_data["target_hw"] = components.get("target_hw")
        cpe_data["other"] = components.get("other")

        return cpe_data
    
    return None

def add_cpe_in_dataset(dataset, extra, cpe) -> pandas.DataFrame:
    """
    Adding a CPE 2.3 information into a DataFrame and returning it updated.
    """
    column_headers = ["github_owner", "github_repo", "dependency",
                      "cpe_uuid", "cpe_uri", "creation_date", "last_midication_date", 
                      "deprecated", "deprecated_by", "part", "vendor", 
                      "product", "version","update", "edition", "language", 
                      "sw_edition", "target_sw", "target_hw", "other"] 
    
    
    extra.update(process_cpe(cpe))
    
    if dataset is None:
        dataset = pandas.DataFrame([extra], columns=column_headers)            
    else:
        new_row = pandas.DataFrame([extra], columns=column_headers)
        dataset = pandas.concat([dataset, new_row], ignore_index=True)

    return dataset

def _search_cpe_with_retry(cpe_wfn_pattern, nvdlib_token):
    """Wrapper de nvdlib.searchCPE com retry para 503/timeout."""
    return with_retry(
        nvdlib.searchCPE,
        cpeMatchString=cpe_wfn_pattern,
        key=nvdlib_token,
        what=f"searchCPE({cpe_wfn_pattern})"
    )

def mine_cpes(nvdlib_token=None) -> None:
    """
    Mine a CPE 2.3 list from NVD repository matching the cpe_wfn_patterns and stores it into a .csv file.
    """
    target = load_target_projects()
    dataset = None
    total = len(target)
    for index, row in target.iterrows():
        cpe_wfn_pattern = row["cpe_wfn_pattern"]
        logger.debug(f"[{index+1}/{total}] Buscando CPE: {cpe_wfn_pattern}")
        cpe_list = _search_cpe_with_retry(cpe_wfn_pattern, nvdlib_token)
        if cpe_list is not None and len(cpe_list) > 0:
            for cpe in cpe_list:
                if cpe is not None:
                    extra = {
                        "github_owner": row["github_owner"], 
                        "github_repo": row["github_repo"], 
                        "dependency": row["dependency"]
                    }
                    dataset = add_cpe_in_dataset(dataset, extra, cpe)
        else:
            logger.debug("It was not able to find CPEs matching the following WFN: {}.".format(cpe_wfn_pattern))
        # Pequena pausa entre requisicoes para reduzir pressao sobre a API,
        # alem do backoff que ja ocorre em caso de erro.
        time.sleep(1)
    if dataset is not None:
        save_cpe_nvd_dataset(dataset)



##########################################
# [Step-2] Mining CVEs from NVD Database #
##########################################


def load_cve_nvd_dataset():
    """
    Loads and return a DataFrame containing all CVEs stored in a .csv file dataset.
    """
    dataset = pandas.read_csv("cve-nvd-dataset.csv",
                              index_col=None, 
                              header=0,
                              delimiter=';',
                              parse_dates=['pub_date', 'mod_date'])
    return dataset.replace({numpy.nan: None})

def save_cve_nvd_dataset(dataset):
    """
    Stores a DataFrame containing all mined CVEs into a .csv file.
    """
    dataset.to_csv("cve-nvd-dataset.csv",
                   sep=';',
                   encoding='utf-8',
                   index=False)

def process_cve(cve):
    if cve is not None:
        cve_data = {}
        cve_data["id"] = cve.id
        cve_data["description"] = cve.descriptions[0].value
        cve_data["src_id"] = cve.sourceIdentifier
        cve_data["pub_date"] = cve.published
        cve_data["mod_date"] = cve.lastModified
        cve_data["status"] = cve.vulnStatus
        
        cve_data["v2severity"] = None
        if hasattr(cve, 'v2severity'):
            cve_data["v2severity"] = cve.v2severity

        cve_data["v2score"] = None
        if hasattr(cve, 'v2score'):
            cve_data["v2score"] = cve.v2score
            
        cve_data["v2vector"] = None
        if hasattr(cve, 'v2vector'):
            cve_data["v2vector"] = cve.v2vector

        cve_data["v30severity"] = None
        if hasattr(cve, 'v30severity'):
            cve_data["v30severity"] = cve.v30severity

        cve_data["v30score"] = None
        if hasattr(cve, 'v30score'):
            cve_data["v30score"] = cve.v30score

        cve_data["v30vector"] = None
        if hasattr(cve, 'v30vector'):
            cve_data["v30vector"] = cve.v30vector

        cve_data["v31severity"] = None
        if hasattr(cve, 'v31severity'):
            cve_data["v31severity"] = cve.v31severity

        cve_data["v31score"] = None
        if hasattr(cve, 'v31score'):
            cve_data["v31score"] = cve.v31score

        cve_data["v31vector"] = None
        if hasattr(cve, 'v31vector'):
            cve_data["v31vector"] = cve.v31vector
    
        cve_data["v40severity"] = None
        if hasattr(cve, 'v40severity'):
            cve_data["v40severity"] = cve.v40severity

        cve_data["v40score"] = None
        if hasattr(cve, 'v40score'):
            cve_data["v40score"] = cve.v40score

        cve_data["v40vector"] = None
        if hasattr(cve, 'v40vector'):
            cve_data["v40vector"] = cve.v40vector

        cve_data["cwe_list"] = None
        if hasattr(cve, 'cwe'):
            cwe_list = []
            for cwe in cve.cwe:
                if re.match(r'CWE-\d{1,7}', cwe.value) is not None:
                    cwe_list.append(cwe.value)
                    cwe_list = list(set(cwe_list))
            if len(cwe_list) > 0:
                cve_data["cwe_list"] = ' '.join(cwe_str for cwe_str in cwe_list)
            else:
                cve_data["cwe_list"] = None
        
        cve_data["cpe_list"] = None
        if hasattr(cve, 'cpe'):
            cve_data["cpe_list"] = ' '.join(cpe_elem.criteria for cpe_elem in cve.cpe)

        cve_data["url_list"] = None
        if hasattr(cve, 'references'):
            cve_data["url_list"] = ' '.join(ref_elem.url for ref_elem in cve.references)

        return cve_data


def add_cve_in_dataset(dataset, extra, cve) -> pandas.DataFrame:
    """
    Adding a CVE information into a DataFrame and returning it updated.
    """
    column_headers = ["github_owner", "github_repo", "dependency",
                      "id", "description", "src_id", 
                      "pub_date", "mod_date", "status", 
                      "v2severity", "v2score", "v2vector", 
                      "v30severity", "v30score", "v30vector",
                      "v31severity", "v31score", "v31vector",
                      "v40severity", "v40score", "v40vector",
                      "cwe_list", "cpe_list", "url_list"] 
    
    extra.update(process_cve(cve))

    if dataset is None:
        dataset = pandas.DataFrame([extra], columns=column_headers)            
    else:
        new_row = pandas.DataFrame([extra], columns=column_headers)
        new_row.dropna(axis=0, how='all', inplace=True)
        if(new_row is None or new_row.empty):
            logger.debug("new_row is None or new_row.empty CVE ID {}".format(extra.get("id")))
        if new_row is not None and not new_row.empty:
            dataset = pandas.concat([dataset, new_row], ignore_index=True)

    return dataset

def _search_cve_by_cpe_with_retry(cpe_uri, nvdlib_token):
    """Wrapper de nvdlib.searchCVE (por CPE) com retry para 503/timeout."""
    return with_retry(
        nvdlib.searchCVE,
        cpeName=cpe_uri,
        key=nvdlib_token,
        what=f"searchCVE(cpeName={cpe_uri})"
    )

def mine_cves(nvdlib_token=None):
    mined_cves = []
    cpe_dataset = load_cpe_nvd_dataset()
    dataset = None
    total = len(cpe_dataset)

    for index, row in cpe_dataset.iterrows():
        cpe_uri = row["cpe_uri"]
        logger.debug(f"[{index+1}/{total}] Buscando CVEs para CPE: {cpe_uri}")
        cve_list = _search_cve_by_cpe_with_retry(cpe_uri, nvdlib_token)
        if cve_list is None:
            logger.warning(f"Falha definitiva ao buscar CVEs para {cpe_uri}. Pulando.")
            continue
        logger.debug(f"CPE {cpe_uri} - {len(cve_list)} CVEs")
        for cve in cve_list:
            if cve is not None and cve.id not in mined_cves:
                logger.debug(f"Adding CVE ID {cve.id}")
                mined_cves.append(cve.id)
                extra = {
                    "github_owner": row["github_owner"], 
                    "github_repo": row["github_repo"], 
                    "dependency": row["dependency"]
                }                
                dataset = add_cve_in_dataset(dataset, extra, cve)
        time.sleep(1)
    if dataset is not None:
        save_cve_nvd_dataset(dataset)

#######################################################
# [Step-3] Mining GHSAs from GitHub Advisory Database #
#######################################################

def load_ghsa_dataset():
    """
    Loads and return a DataFrame containing all GHSAs stored in a .csv file.
    """
    dataset = pandas.read_csv("ghsa-dataset.csv",
                              index_col=None,
                              header=0,
                              delimiter=';',
                              parse_dates=['published_at'])
    return dataset.replace({numpy.nan: None})

    # return dataset.where(pandas.notnull(dataset), None)

def save_ghsa_dataset(dataset):
    """
    Stores a DataFrame containing all mined GHSAs into a .csv file.
    """
    dataset.to_csv("ghsa-dataset.csv", 
                   sep=';', 
                    encoding='utf-8', 
                    index=False)
    
def add_ghsa_in_dataset(dataset, extra, ghsa) -> pandas.DataFrame:
    """
    Adding a GHSA information into a DataFrame and returning it updated.
    """
    column_headers = ["github_owner", "github_repo", "dependency", "ghsa_id", 
                      "severity", "published_at", "cve_list", "html_url"] 
    
    extra.update(ghsa)

    if dataset is None:
        dataset = pandas.DataFrame([extra], columns=column_headers)            
    else:        
        new_row = pandas.DataFrame([extra], columns=column_headers)
        dataset = pandas.concat([dataset, new_row], ignore_index=True)

    return dataset

def _github_get_with_retry(url, headers, what="GitHub GET"):
    """Wrapper de requests.get com retry para 503/timeout/rate-limit transitorio."""
    def _do_request():
        resp = requests.get(url, headers=headers, timeout=30)
        # 403 com rate limit e tratado separadamente (nao e erro transitorio comum,
        # mas vale verificar o cabecalho antes de propagar).
        if resp.status_code == 403 and "X-RateLimit-Remaining" in resp.headers:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining == "0":
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time(), 1)
                logger.warning(f"Rate limit do GitHub esgotado. Aguardando {wait:.0f}s.")
                time.sleep(wait)
                resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp
    return with_retry(_do_request, what=what)

def mine_ghsas(github_token=None) -> None:
    """
    Mine a GHSAs list from GitHub Advisory Database.
    """
    target = load_target_projects()
    dataset = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
    }
    mined_repos = []
    for index, row in target.iterrows():
        owner = row["github_owner"]
        name = row["github_repo"]
        repo_id = owner + "/" + name
        if repo_id not in mined_repos:
            mined_repos.append(repo_id)
            advisories_url = f"https://api.github.com/repos/{owner}/{name}/security-advisories"
            logger.debug(advisories_url)

            resp = _github_get_with_retry(advisories_url, headers, what=f"security-advisories({repo_id})")
            if resp is None:
                logger.warning(f"Falha definitiva ao buscar advisories de {repo_id}. Pulando.")
                continue
            advisories = resp.json()

            extra = {
                "github_owner": row["github_owner"], 
                "github_repo": row["github_repo"], 
                "dependency": row["dependency"]
            }
            ghsa = {}
            for advisory in advisories:
                ghsa_id = advisory["ghsa_id"]
                logger.debug(f" {repo_id} : {ghsa_id}")
                details_url = f"https://api.github.com/repos/{owner}/{name}/security-advisories/{ghsa_id}"
                details_resp = _github_get_with_retry(details_url, headers, what=f"advisory-details({ghsa_id})")
                if details_resp is None:
                    logger.warning(f"Falha definitiva ao buscar detalhes de {ghsa_id}. Pulando.")
                    continue
                details = details_resp.json()
                ghsa["ghsa_id"] = details["ghsa_id"]
                ghsa["severity"] = details.get("severity", "UNKNOWN")
                ghsa["published_at"] = details["published_at"]
                ghsa["cve_list"] = None
                cve_list = [identifier["value"] for identifier in details.get("identifiers", []) if identifier["type"] == "CVE"]
                if cve_list is not None and len(cve_list) > 0:
                    ghsa["cve_list"] = ' '.join(cve_id for cve_id in cve_list)
                ghsa["html_url"] = details["html_url"]
                
                if len(ghsa) > 0:
                    dataset = add_ghsa_in_dataset(dataset, extra, ghsa)

    if dataset is not None:
        save_ghsa_dataset(dataset)

##########################################################
# [Step-4] Mining CVEs linked to GHSAs from NVD Database #
##########################################################
def load_cves_ghsa_dataset():
    """
    Loads and return a DataFrame containing all CVEs stored in a .csv file dataset.
    """
    dataset = pandas.read_csv("ghsa-cve-nvd-dataset.csv",
                              index_col=None, 
                              header=0,
                              delimiter=';',
                              parse_dates=['pub_date', 'mod_date'])
    return dataset.replace({numpy.nan: None})

def save_cves_ghsa_dataset(dataset):
    """
    Stores a DataFrame containing all mined CVEs linked to 
    GHSAs from NVD Database into a .csv file.
    """
    dataset.to_csv("ghsa-cve-nvd-dataset.csv", 
                   sep=';',
                   encoding='utf-8',
                   index=False)

def _search_cve_by_id_with_retry(cve_id, nvdlib_token):
    """Wrapper de nvdlib.searchCVE (por CVE ID) com retry para 503/timeout."""
    return with_retry(
        nvdlib.searchCVE,
        cveId=cve_id,
        key=nvdlib_token,
        what=f"searchCVE(cveId={cve_id})"
    )

def mine_cves_ghsas(nvdlib_token=None):
    """
    Mining CVEs linked to GHSAs from NVD Database.
    """
    ghsas_dataset = load_ghsa_dataset()
    dataset = load_cve_nvd_dataset()
    mined_cves = dataset["id"].to_list()

    for index, row in ghsas_dataset.iterrows():
        if row["cve_list"] is not None:
            cve_list = row["cve_list"].split()
            ghsa_id = row["ghsa_id"]
            if len(cve_list) > 0:
                for cve_id in cve_list:
                    if cve_id is not None:
                        logger.debug(f"GHSA {ghsa_id} - CVE ID {cve_id}")
                        cve_result = _search_cve_by_id_with_retry(cve_id, nvdlib_token)
                        if not cve_result:
                            logger.warning(f"Falha definitiva ao buscar {cve_id}. Pulando.")
                            time.sleep(1)
                            continue
                        cve = cve_result[0]
                        if cve is not None and cve.id not in mined_cves:
                            logger.debug(f"Adding CVE ID {cve.id}")
                            mined_cves.append(cve.id)
                            extra = {
                                "github_owner": row["github_owner"], 
                                "github_repo": row["github_repo"], 
                                "dependency": row["dependency"]
                            }                
                            dataset = add_cve_in_dataset(dataset, extra, cve)
                        time.sleep(1)
    if dataset is not None:
        save_cves_ghsa_dataset(dataset)


###############################################################################
# [Step-5] Mining Fixing Commits Information linked to CVEs from NVD Database #
###############################################################################
def add_cve_fixing_commit_in_dataset(dataset, cve_fixing_commit) -> pandas.DataFrame:
    """
    Adding a CVEs fixing commit information into a DataFrame and returning it updated.
    """
    column_headers = ["id", "github_owner", "github_repo", "dependency",
                      "commit_sha", "commit_url" , "no_files",
                      "additions", "deletions", "changes"] 
    

    if dataset is None:
        dataset = pandas.DataFrame([cve_fixing_commit], columns=column_headers)            
    else:
        new_row = pandas.DataFrame([cve_fixing_commit], columns=column_headers)
        new_row.dropna(axis=0, how='all', inplace=True)
        if(new_row is None or new_row.empty):
            logger.debug("new_row is None or new_row.empty CVE ID {}".format(cve_fixing_commit.get("id")))
        if new_row is not None and not new_row.empty:
            dataset = pandas.concat([dataset, new_row], ignore_index=True)

    return dataset

def load_cves_fixing_commits_dataset():
    """
    Loads and return a DataFrame containing all Fixing Commits Information 
    linked to CVEs stored in a .csv file dataset.
    """
    dataset = pandas.read_csv("cves-fixing-commits-dataset.csv",
                              index_col=None, 
                              header=0,
                              delimiter=';')
    return dataset.replace({numpy.nan: None})
    
def save_cves_fixing_commits_dataset(dataset):
    """
    Stores a DataFrame containing all Fixing Commits Information 
    linked to CVEs from NVD Database into a .csv file.
    """
    dataset.to_csv("cves-fixing-commits-dataset.csv", 
                   sep=';',
                   encoding='utf-8',
                   index=False)

def is_fixing_commit_url(url:str=None):
    commit_pattern = r'[0-9a-fA-F]{40}$'
    return re.search(commit_pattern, url) is not None

def extract_fixing_commit_sha(url:str=None):
    commit_pattern = r'[0-9a-fA-F]{40}$'
    match = re.search(commit_pattern, url)
    return match.group(0) if match else None

def is_github_fixing_commit_url(url:str=None):
    commit_pattern = r'https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{40}$'
    return re.search(commit_pattern, url) is not None

def parse_github_fixing_commit_url(url:str=None):
    """
    Expects URLs like:
      https://github.com/<owner>/<repo>/commit/<sha>
    Returns (owner, repo, sha)
    """
    u = urlparse(url)
    if u.netloc not in {"github.com", "www.github.com"}:
        raise ValueError("Only github.com URLs are supported in this script.")
    matching = re.match(r"^/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})/?$", u.path)
    if not matching:
        raise ValueError("Not a valid GitHub commit URL.")
    owner, repo, sha = matching.group(1), matching.group(2), matching.group(3)
    return owner, repo, sha

def retrieve_fixing_commit_info(github_token=None, url:str=None):
    owner, repo, sha = parse_github_fixing_commit_url(url)
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "User-Agent": "commit-files-script",
    }
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    response = _github_get_with_retry(commit_url, headers, what=f"commit-files({owner}/{repo}@{sha[:8]})")
    if response is not None and response.status_code == 200:
        files_map = {
            "no_files": 0,
            "additions": 0,
            "deletions": 0,
            "changes": 0
        }
        response = response.json()
        for file in response.get("files"):
            files_map["no_files"] += 1
            files_map["additions"] += file["additions"]
            files_map["deletions"] += file["deletions"]
            files_map["changes"] += file["changes"]
        return files_map
    
    return None

def mine_cves_fixing_commits(github_token=None) -> None:
    cves_ghsa_dataset = load_cves_ghsa_dataset()
    dataset = None

    for index, row in cves_ghsa_dataset.iterrows():
        url_list = row.url_list.split()
        commit_sha_set = set() 
        for url in url_list:
            if is_fixing_commit_url(url):
                sha = extract_fixing_commit_sha(url)
                if sha in commit_sha_set:
                    continue
                commit_sha_set.add(sha)
                cve_fixing_commit = {
                    "id": row["id"],
                    "github_owner": row.github_owner,
                    "github_repo": row.github_repo,
                    "dependency": row.dependency,
                    "commit_sha": sha,
                    "commit_url": url,
                    "no_files": None,
                    "additions": None,
                    "deletions": None,
                    "changes": None,
                }

                if is_github_fixing_commit_url(url):
                    files_map = retrieve_fixing_commit_info(github_token, url)
                    if files_map is not None:
                        cve_fixing_commit["no_files"] = files_map["no_files"]
                        cve_fixing_commit["additions"] = files_map["additions"]
                        cve_fixing_commit["deletions"] = files_map["deletions"]
                        cve_fixing_commit["changes"] = files_map["changes"]
                        dataset = add_cve_fixing_commit_in_dataset(dataset, cve_fixing_commit)
                else:
                    dataset = add_cve_fixing_commit_in_dataset(dataset, cve_fixing_commit)
    
    if dataset is not None:
        save_cves_fixing_commits_dataset(dataset)

def start(nvdlib_token=None, github_token=None):
    logging.basicConfig(filename='pipeline.log', encoding='utf-8', level=logging.DEBUG)
    if nvdlib_token is not None and github_token is not None:
        logger.debug("[Step-1 Start] Mining CPEs from NVD Database")
        mine_cpes(nvdlib_token)
        logger.debug("\n[Step-1 Stop]")
        logger.debug("\n======================================================================")

        logger.debug("\n[Step-2 Start] Mining CVEs from NVD Database")
        mine_cves(nvdlib_token)
        logger.debug("\n[Step-2 Stop]")
        logger.debug("\n======================================================================")

        logger.debug("\n[Step-3 Start] Mining GHSAs from GitHub Advisory Database")
        mine_ghsas(github_token)
        logger.debug("\n[Step-3 Stop]")

        logger.debug("\n[Step-4 Start] Mining CVEs linked to GHSAs from NVD Database")
        mine_cves_ghsas(nvdlib_token)
        logger.debug("\n[Step-4 Stop]")

        logger.debug("\n[Step-5 Start] Mining Fixing Commits Information linked to CVEs from NVD Database")
        mine_cves_fixing_commits(github_token)
        logger.debug("\n[Step-5 Stop]")        
    else:
        logger.debug("Unable to run the pipeline, you must provide the NVD API and GitHub API access keys/tokens.")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        nvdlib_token = str(sys.argv[1])
        github_token = str(sys.argv[2])
        print(nvdlib_token)
        print(github_token)
        start(nvdlib_token, github_token)
    else:
        print("You must provide the NVD API access key and GitHub API access token.")