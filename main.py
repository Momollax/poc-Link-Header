from urllib.parse import urlparse,urljoin
import requests
import re
import json
from outils.user_agents import read_user_agents, get_random_user_agent
from tqdm import tqdm
from bs4 import BeautifulSoup
from usp.tree import sitemap_tree_for_homepage

#---------------------------------------------------------------------- Variables
url_requested = []
url_to_request = []
all_urls = []
global target_domain

user_agents = read_user_agents('outils/data/user_agents.txt')
headers = {'User-Agent': get_random_user_agent(user_agents)}
#---------------------------------------------------------------------- Print in file
def write_links_to_file(filename, links):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for link in links:
                file.write(link + '\n')
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier {filename}: {e}")

def write_links_to_file_append(filename, links):
    try:
        with open(filename, 'a', encoding='utf-8') as file:
            for link in links:
                file.write(link + '\n')
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier {filename}: {e}")
#---------------------------------------------------------------------- Utils
def is_same_domain(url):
    # Vérifie si l'URL appartient au domaine cible
    parsed_url = urlparse(url)
    return parsed_url.netloc == target_domain

def is_subdomain(url):
    """
    Vérifie si l'URL donnée appartient à l'un des domaines dans la liste.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.endswith(target_domain):
        return True
    return False

#---------------------------------------------------------------------- Extract link from xml
def extract_link_from_xml():
    http_target_url = "https://" + target_domain
    tree = sitemap_tree_for_homepage(http_target_url)
    for page in tree.all_pages():
        if page.url not in url_to_request and page.url not in all_urls:
            url_to_request.append(page.url)
            all_urls.append(page.url)
#---------------------------------------------------------------------- Get subdomains
def get_subdomains():
    url = f'https://crt.sh/?q=%.{target_domain}&output=json'
    try:
        response = requests.get(url)
        data = response.json()
        subdomains = set()
        for entry in data:
            subdomain = entry['name_value'].strip()
            subdomains.add(subdomain)
        for link in subdomains:
            u = url_to_request.copy()
            if link not in u and '*' not in link and link not in all_urls:
                url_to_request.append(link)
                all_urls.append(link)
    except Exception as e:
        print(f"Erreur lors de la récupération des sous-domaines : {e}")
        return set()


    
#---------------------------------------------------------------------- extract urls from header Link
def get_header_link_data(response):
    link_header = response.headers.get('Link')
    new_links = []
    try:
        base_url = target_domain.rstrip('/')
        matches = re.finditer(r'<([^>]+)>', link_header)
        for match in matches:
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if is_same_domain(full_url):
                new_links.append(full_url)
            for link in new_links:
                if link not in url_to_request and link not in all_urls:
                    url_to_request.append(full_url)
                    all_urls.append(full_url)
    except Exception as e:
        pass

#---------------------------------------------------------------------- 
def analyze_page_content(url, content):
    # Analyser le contenu de la page à la recherche de la clé API
    api_key = search_api_key_in_page(content)

    if api_key:
        #print(f"Clé API trouvée sur la page {url}: {api_key}")
        # Faites ce que vous devez faire avec la clé API, par exemple, l'enregistrer dans un fichier
        with open('api_keys' + target_domain+ ".txt", 'a') as api_file:
            api_file.write(f"{api_key} {url}\n")

def search_api_key_in_page(content):
    api_key_patterns = [
    r'''glpat-[0-9a-zA-Z\-]{20}''',                             # GitLab Personal Access Token
    r'''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}''',  # AWS Access Key
    r'''-----BEGIN PRIVATE KEY-----''',                        # PKCS8 Private Key
    r'''-----BEGIN RSA PRIVATE KEY-----''',                    # RSA Private Key
    r'''-----BEGIN OPENSSH PRIVATE KEY-----''',                # SSH Private Key
    r'''-----BEGIN PGP PRIVATE KEY BLOCK-----''',              # PGP Private Key
    r'''ghp_[0-9a-zA-Z]{36}''',                                 # GitHub Personal Access Token
    r'''gho_[0-9a-zA-Z]{36}''',                                 # GitHub OAuth Access Token
    r'''-----BEGIN DSA PRIVATE KEY-----''',                    # SSH (DSA) Private Key
    r'''-----BEGIN EC PRIVATE KEY-----''',                     # SSH (EC) Private Key
    r'''(ghu|ghs)_[0-9a-zA-Z]{36}''',                          # GitHub App Token
    r'''ghr_[0-9a-zA-Z]{76}''',                                 # GitHub Refresh Token
    r'''shpss_[a-fA-F0-9]{32}''',                               # Shopify Shared Secret
    r'''shpat_[a-fA-F0-9]{32}''',                               # Shopify Access Token
    r'''shpca_[a-fA-F0-9]{32}''',                               # Shopify Custom App Access Token
    r'''shppa_[a-fA-F0-9]{32}''',                               # Shopify Private App Access Token
    r'''xox[baprs]-([0-9a-zA-Z]{10,48})?''',                   # Slack Access Token
    r'''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}''',            # Stripe Access Token
    r'''pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}''',         # PyPI Upload Token
    r'''\"type\": \"service_account\"''',                      # Google (GCP) Service-account
    r'''(?i)(heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]''',  # Heroku API Key
    r'''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}''',  # Slack Webhook
    r'''SK[0-9a-fA-F]{32}''',                                  # Twilio API Key
    r'''AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}''',  # Age Secret Key
    r'''(?i)(facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]''',  # Facebook Token
    r'''(?i)(twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{35,44})['\"]''',  # Twitter Token
    r'''(?i)(adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]''',  # Adobe Client ID (Oauth Web)
    r'''(p8e-)(?i)[a-z0-9]{32}''',                             # Adobe Client Secret
    r'''(LTAI)(?i)[a-z0-9]{20}''',                             # Alibaba AccessKey ID
    r'''(?i)(alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]''',  # Alibaba Secret Key
    r'''(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{16})['\"]''',  # Asana Client ID
    r'''(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]''',  # Asana Client Secret
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](key[a-zA-Z0-9]{13})['\"]''',  # Airtable API Key
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](app[a-zA-Z0-9]{14})['\"]''',  # Airtable App Key
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](api[a-zA-Z0-9]{17})['\"]''',  # Airtable API Secret
    r'''(pk|sk)_test_[0-9a-zA-Z]{24}''',                       # Postman API Key
    r'''(pk|sk)_live_[0-9a-zA-Z]{24}''',                       # Postman API Key
    r'''psk-[0-9a-zA-Z]{27}''',                                # PagerDuty Integration Key
    r'''sk-live-[0-9a-zA-Z]{32}''',                            # Plaid Secret Key
    r'''(my-)?api-?[0-9a-zA-Z]{36}''',                         # Generic API Key
    r'''(PRIVATE-KEY-)([a-zA-Z0-9_-]{22,250})(-PUBLIC-KEY-)''',  # SSH Private Key (with markers)
    r'''bearer [a-zA-Z0-9-_]{100,}''',                         # Bearer Token
    r'''authorization[:= ].{0,5}['\"]?[bB]earer[-_]?[tT]oken['\"]?[ :]+[a-zA-Z0-9-_]{100,}''',  # Authorization Bearer Token
    r'''apikey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',   # Generic API Key
    r'''api_key[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API Key
    r'''secret[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',   # Generic Secret
    r'''access[-_]?token[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{50,}['\"]?''',  # Generic Access Token
    r'''token[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',     # Generic Token
    r'''session[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Session Token
    r'''pass[word]+[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',  # Generic Password
    r'''pwd[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',        # Generic Password
    r'''key[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',      # Generic Key
    r'''(api|token)[-._]?[sS]ecret[-_]?[kK]ey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Secret Key
    r'''(api|token)[-._]?[kK]ey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Key
    r'''(api|token)[-._]?[pP]assword[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',  # Generic Password
    r'''(api|token)[-._]?[tT]oken[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Token
    r'''(api|token)[-._]?[sS]ession[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Session Token
    r'''(api|token)[-._]?[aA]uth[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Auth Token
    r'''(api|token)[-._]?[cC]ode[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic Code Token
    r'''(api|token)[-._]?[iI]d[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{16,}['\"]?''',  # Generic ID Token
    r'''(api|token)[-._]?[uU]ser[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{16,}['\"]?''',  # Generic User Token
    r'''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}''',  # Stripe Access Token
    r'''(?i)((key|api|token|secret|password)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]''',  # Generic API Key
]

    found_keys = []
    total_patterns = len(api_key_patterns)

    with tqdm(total=total_patterns, desc="Searching API Keys", unit="pattern") as pbar:
        for pattern in api_key_patterns:
            
            try:
                matches = re.findall(pattern, content)
                found_keys.extend(matches)
                pbar.update(1)  # Met à jour la barre de progression pour chaque motif traité
            except:
                print("error with patern:", pattern)
                pass

    return found_keys

#---------------------------------------------------------------------- 
def get_data_from_url(link):
    if link.startswith("http://") or link.startswith("https://"):
        url = link
    else:
        url = "http://" + link
    url_requested.append(link)
    if is_subdomain(url):
        print("Requêtes restantes:", len(url_to_request), "Faites:", len(url_requested), url)
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            get_header_link_data(response)
            if response.status_code == 200:
                try: 
                    contenu_json = response.json()
                    liens = []
                    try:
                        explorer_json(contenu_json, liens, target_domain)
                    except:
                        pass
                    analyze_page_content(link, response.text)
                    write_links_to_file_append('requested_json_' + target_domain+ ".txt", [f"{link} - Status Code: {response.status_code}"])
                except json.decoder.JSONDecodeError:
                    try:
                        explorer_html(response.text)
                        analyze_page_content(link, response.text)
                        write_links_to_file_append('requested_html_' + target_domain+ ".txt", [f"{link} - Status Code: {response.status_code}"])
                    except:
                        print("error, not json nor html")
            else:
                write_links_to_file_append('requested_error_' + target_domain+ ".txt", [f"{link} - Status Code: {response.status_code}"])
        except ConnectionError as ce:
            print(f"Erreur de connexion pour l'URL {url}")
        except requests.exceptions.RequestException as e:
            print(f"Erreur pendant la requête pour l'URL {url}")
       
#----------------------------------------------------------------------
def explorer_html(response):
    unique_urls = set()
    soup = BeautifulSoup(response, 'html.parser')
    resource_elements = soup.find_all(['a', 'img', 'link', 'script'], href=True) + soup.find_all(['a', 'img', 'link', 'script'], src=True)
    for element in resource_elements:
        if 'href' in element.attrs:
            url = urljoin(target_domain, element['href'])
            unique_urls.add(url)
        elif 'src' in element.attrs:
            url = urljoin(target_domain, element['src'])
            unique_urls.add(url)
    file_links = soup.find_all('a', href=re.compile(r'\.pdf$|\.txt$', re.IGNORECASE))
    for link in file_links:
        file_url = urljoin(target_domain, link['href'])
        unique_urls.add(file_url)
    extracted_urls = list(unique_urls)
    for url in extracted_urls:
        if url not in url_to_request and url not in all_urls:
            url_to_request.append(url)
            all_urls.append(url)

def explorer_json(obj, liens, target_domain):
    if isinstance(obj, list):
        for item in obj:
            explorer_json(item, liens, target_domain)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key in ('href', 'src') and isinstance(value, str) and value not in url_to_request and value not in all_urls:
                url_to_request.append(value)
                all_urls.append(value)
            elif isinstance(value, (list, dict)):
                explorer_json(value, liens, target_domain)

#----------------------------------------------------------------------
def main():
    global target_domain

    target_domain = input("Veuillez entrer l'url a target : ")
    url_to_request.append(target_domain)
    all_urls.append(target_domain)
    extract_link_from_xml()
    get_subdomains()
    while len(url_to_request) > 0:
        links_to_process = url_to_request.copy()
        for link in links_to_process:
            if link not in url_requested:
                url_to_request.remove(link)
                get_data_from_url(link)
                write_links_to_file("url_requested_" + target_domain+ ".txt", url_requested)   
                write_links_to_file("url_to_request_" + target_domain+ ".txt", url_to_request)   
                write_links_to_file("all_url_" + target_domain+ ".txt", all_urls)   
if __name__ == "__main__":
    main()