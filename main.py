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
global root_url
user_agents = read_user_agents('outils/data/user_agents.txt')
#headers = {'User-Agent': get_random_user_agent(user_agents)}
headers = {'User-Agent': "X-Intigriti-Username: Momollax"}
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

    if root_url in url:
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
def get_subdomains(sub):
    prefixes = ["https://", "http://", "www.", "http://www.", "https://www."]
    subs = []
    
    for domain in sub:
        for prefix in prefixes:
            
            try:
                full_domain = prefix + domain
                response = requests.get(full_domain, headers=headers, timeout=2)
                print(full_domain, response.status_code)
                
                if response.ok:
                    
                    subs.append(full_domain)
                    url_to_request.append(full_domain)
                break  # Sortir de la boucle si la requête réussit
            except requests.RequestException as e:
                pass
        else:
            # Exécuté si la boucle interne se termine sans interruption (c'est-à-dire si aucune requête n'a réussi)
            print("Aucun préfixe n'a fonctionné pour", domain)
    
    return subs

def search_subdomains(url):
    sub = []
    csub = []
    csub.append(url)
    print(f"Recherche des sous-domaines pour {url}...")
    try:
        response = requests.get(f'https://crt.sh/?q={url}&output=json', headers=headers)
        if response.ok:
            data = response.json()
            subdomains = {entry['name_value'].strip() for entry in data}
            
            for subdomain in subdomains:
                if subdomain not in sub:
                    sub.append(subdomain)
            for s in sub:
                sub_list = s.split('\n')
                for url in sub_list:
                    if url not in csub :
                        csub.append(url)
            return csub
        else:
            print(f"Erreur lors de la recherche des sous-domaines : {response.text}")

    except Exception as e:  
        print(e)
        search_subdomains("www." + url)

    
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
    print("Searching API Keys in ", url)
    api_key = search_api_key_in_page(content)

    if api_key:
        #print(f"Clé API trouvée sur la page {url}: {api_key}")
        # Faites ce que vous devez faire avec la clé API, par exemple, l'enregistrer dans un fichier
        with open('api_keys' + ".txt", 'a') as api_file:
            api_file.write(f"{api_key} {url} \n")
        try:
            with open("azeaze.txt", 'a') as data:
                data.write(f"URL: {url}\nContent: {content}\n")
        except Exception as e:
            print(e)
        exit()


def search_api_key_in_page(content):
    api_key_patterns = [
    r'''ghp_[0-9a-zA-Z]{36}''',      # GitHub Personal Access Token
    r'''gho_[0-9a-zA-Z]{36}''',      # GitHub OAuth Token
    r'''(ghu|ghs)_[0-9a-zA-Z]{36}''',  # GitHub Gist Token or GitHub App Token
    r'''ghr_[0-9a-zA-Z]{76}''',      # GitHub Gist Raw Token
    r'''shpss_[a-fA-F0-9]{32}''',    # Shopify Private App Secret
    r'''shpat_[a-fA-F0-9]{32}''',    # Shopify Private App Token
    r'''shpca_[a-fA-F0-9]{32}''',    # Shopify Custom App Token
    r'''shppa_[a-fA-F0-9]{32}''',    # Shopify Partner App Token
    r'''xox[baprs]-([0-9a-zA-Z]{10,48})?''',  # Slack Token
    r'''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}''',  # Slack Webhook URL
    r'''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}''',  # Stripe API Key (test or live)
    r'''pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}''',  # PyPI API Key
    r'''\"type\": \"service_account\"''',  # Google Cloud JSON Key for service account
    r'''(?i)(heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]''',  # Heroku API Key
    r'''SK[0-9a-fA-F]{32}''',  # SendGrid Auth Token
    r'''AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}''',  # Age Protocol Secret Key
    r'''(?i)(facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]''',  # Facebook API Key
    r'''(?i)(twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{35,44})['\"]''',  # Twitter API Key
    r'''(?i)(adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]''',  # Adobe API Key
    r'''(p8e-)(?i)[a-z0-9]{32}''',  # P8e Protocol Key
    r'''(LTAI)(?i)[a-z0-9]{20}''',  # Alibaba Cloud Access Key
    r'''(?i)(alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]''',  # Alibaba Cloud API Key
    r'''(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{16})['\"]''',  # Asana API Key
    r'''(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]''',  # Asana OAuth Token
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](key[a-zA-Z0-9]{13})['\"]''',  # Airtable API Key
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](app[a-zA-Z0-9]{14})['\"]''',  # Airtable App Key
    r'''(?i)(airtable[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](api[a-zA-Z0-9]{17})['\"]''',  # Airtable API Key
    r'''(pk|sk)_test_[0-9a-zA-Z]{24}''',  # Custom Test Key
    r'''(pk|sk)_live_[0-9a-zA-Z]{24}''',  # Custom Live Key
    r'''psk-[0-9a-zA-Z]{27}''',  # Custom Key
    r'''sk-live-[0-9a-zA-Z]{32}''',  # Custom Key
    r'''(my-)?api-?[0-9a-zA-Z]{36}''',  # Custom API Key
    r'''(PRIVATE-KEY-)([a-zA-Z0-9_-]{22,250})(-PUBLIC-KEY-)''',  # Custom Key Pair
    r'''bearer [a-zA-Z0-9-_]{100,}''',  # Bearer Token
    r'''authorization[:= ].{0,5}['\"]?[bB]earer[-_]?[tT]oken['\"]?[ :]+[a-zA-Z0-9-_]{100,}''',  # Authorization Bearer Token
    r'''apikey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # API Key
    r'''api_key[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # API Key
    r'''secret[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Secret
    r'''access[-_]?token[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{50,}['\"]?''',  # Access Token
    r'''token[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Token
    r'''session[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Session
    r'''pass[word]+[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',  # Password
    r'''pwd[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',  # Password
    r'''key[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Key
    r'''(api|token)[-._]?[sS]ecret[-_]?[kK]ey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Secret Key
    r'''(api|token)[-._]?[kK]ey[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Key
    r'''(api|token)[-._]?[pP]assword[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{8,}['\"]?''',  # Generic API/Token Password
    r'''(api|token)[-._]?[tT]oken[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Token
    r'''(api|token)[-._]?[sS]ession[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Session
    r'''(api|token)[-._]?[aA]uth[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Auth
    r'''(api|token)[-._]?[cC]ode[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{32,}['\"]?''',  # Generic API/Token Code
    r'''(api|token)[-._]?[iI]d[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{16,}['\"]?''',  # Generic API/Token ID
    r'''(api|token)[-._]?[uU]ser[:= ].{0,5}['\"]?[a-zA-Z0-9-_]{16,}['\"]?''',  # Generic API/Token User
    r'''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}''',  # Custom Test/Live Key
    r'''(?i)((key|api|token|secret|password)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]''',  # Custom Generic Key
    r'''(GDAI)(?i)[a-z0-9]{20}''',  # Google Drive API Key
    r'''sk_live_[0-9a-zA-Z]{24}''',  # Custom Live Key
    r'''sk_test_[0-9a-zA-Z]{24}''',  # Custom Test Key
    r'''sq0atp-[0-9A-Za-z\-_]{22}''',  # Square OAuth Token
    r'''sq0csp-[0-9A-Za-z\-_]{43}''',  # Square Application Secret
    r'''sq0cp-[0-9A-Za-z\-_]{31}''',  # Square Personal Access Token
    r'''sq0[a-z]p-[0-9A-Za-z\-_]{53}''',  # Square Payment Form Key
    r'''eyr[a-z0-9]{2,}'(?:&|$)''',  # Square Ephemeral Key
    r'''(access|refresh)_token.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,1024}.(id_token|access_token|refresh_token)''',  # OAuth Token with ID Token, Access Token, or Refresh Token
    r'''Bearer.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,512}''',  # Bearer Token
    r'''(consumer|api|application|access)_key.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,512}''',  # Generic Key
    r'''[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}''',  # Credit Card Format (e.g., 1234-5678-9012-3456)
    r'''([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})(\+\d{1,2}\s?)?(\d{3}|\(\d{3}\))([-.\s]?)\d{3}([-.\s]?)\d{4}''',  # Email Format (e.g., user@example.com)
    r'''document\.write''',
    r'''document\.writeln''',
    r'''document\.location.href''',
    r'''ReactPropTypesSecret''',
    r'''pixelborn-''',
    r'''herokuapp''',
    r'''location.search''',
    r'''links''',
    r'''onclick=''',
    r'''internal''',
    r'''/api/''',
    r'''/api/(?P<version>v\d+)/''',
    r'''redirect_url:''',
    r'''client_id=''',
    r'''admin''',
    r'''appspot''',
    r'''firebase''',
    r'''testuser''',
    r'''testing''',
    r'''allow-access-from domain="*"'''
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
                

    return found_keys

#---------------------------------------------------------------------- 
def get_data_from_url(link):
    global target_domain
    if link.startswith('/'):
        url = "http://" + target_domain + link
    elif link.startswith("http://") or link.startswith("https://"):
        url = link
    else:
        url = "http://" + link
    if url.endswith(".png") or url.endswith(".jpg") or url.endswith(".pdf"):
        return
    if is_subdomain(url):
        url_requested.append(url)
        try:
            print("Requêtes restantes:", len(url_to_request), "Faites:", len(url_requested), url)
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            get_header_link_data(response)
            if response.ok:
                check_cookie(response, url)
                try: 
                    contenu_json = response.json()
                    liens = []
                    try:
                        explorer_json(contenu_json, liens, target_domain)
                    except:
                        pass
                    analyze_page_content(link, response.text)
                    write_links_to_file_append('requested_json_' + ".txt", [f"{link} - Status Code: {response.status_code}"])
                except json.decoder.JSONDecodeError:
                    try:
                        explorer_html(response.text)
                        analyze_page_content(link, response.text)
                        write_links_to_file_append('requested_html_' + ".txt", [f"{link} - Status Code: {response.status_code}"])
                    except:
                        print("error, not json nor html")
                        write_links_to_file_append('error' + ".txt", [f"{link} - Status Code: {response.status_code}, {response.content}"])
            else:
                write_links_to_file_append('requested_error_' + ".txt", [f"{link} - Status Code: {response.status_code}"])
        except ConnectionError as ce:
            print(f"Erreur de connexion pour l'URL {url}")
        except requests.exceptions.RequestException as e:
            print(f"Erreur pendant la requête pour l'URL {url}", e)
    else:
        print("out of domain", url)


def check_cookie(response, url):
    for cookie in response.cookies:
        if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.secure:
            write_links_to_file_append('bad_cookies' + ".txt", [f"{url} - Status Code: {response.cookies} not HttpOnly"])

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
    global root_url
    prefixes = ["https://", "http://", "www.", "http://www.", "https://www."]
    target_domain = input("Veuillez entrer l'url a target : ")
    root_url = target_domain
    for pre in prefixes:
        if root_url.startswith(pre):
            root_url = root_url.replace(pre, "")
    
    url_to_request.append(target_domain)
    all_urls.append(target_domain)
    #extract_link_from_xml()
    sub = search_subdomains(target_domain)

    sub = get_subdomains(sub)
    sub.append(target_domain)
    for subdomain in sub:
        target_domain = subdomain
        while len(url_to_request) > 0:
            print(len(url_to_request))
            links_to_process = url_to_request.copy()
            for link in links_to_process:
                if link not in url_requested:
                    url_to_request.remove(link)
                    get_data_from_url(link)
                    write_links_to_file("url_requested_" + ".txt", url_requested)   
                    write_links_to_file("url_to_request_" + ".txt", url_to_request)   
                    write_links_to_file("all_url_" + ".txt", all_urls)   

if __name__ == "__main__":
    main()