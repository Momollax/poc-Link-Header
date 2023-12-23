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
def get_subdomains(sub):
    prefixes = ["https://", "http://", "www.", "http://www.", "https://www."]
    
    for domain in sub:
        for prefix in prefixes:
            try:
                full_domain = prefix + domain
                response = requests.get(full_domain, headers=headers)
                print(full_domain, response.status_code)
                url_to_request.append(full_domain)
                break  # Sortir de la boucle si la requête réussit
            except requests.RequestException as e:
                pass
        else:
            # Exécuté si la boucle interne se termine sans interruption (c'est-à-dire si aucune requête n'a réussi)
            print("Aucun préfixe n'a fonctionné pour", domain)

def search_subdomains(url):
    sub = []
    csub = []
    print(f"Recherche des sous-domaines pour {url}...")
    try:
        response = requests.get(f'https://crt.sh/?q=%.{url}&output=json', headers=headers)
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
        print(f"Erreur lors de la recherche des sous-domaines : {e}")

    
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
    r'''(LTAI)(?i)[a-z0-9]{20}''',                             # Alibaba Cloud Access Key
    r'''(GDAI)(?i)[a-z0-9]{20}''',                             # Alibaba Cloud Secret Key
    r'''AIza[0-9A-Za-z-_]{35}''',                              # Android Key
    r'''AIza[0-9A-Za-z-_]{39}''',                              # Android Key
    r'''AIza[0-9A-Za-z-_]{63}''',                              # Android Key
    r'''AIzaSy[0-9A-Za-z-_]{66}''',                            # Android Key
    r'''AIzaSy[0-9A-Za-z-_]{86}''',                            # Android Key
    r'''AIzaSy[0-9A-Za-z-_]{95}''',                            # Android Key
    r'''sk_live_[0-9a-zA-Z]{24}''',                            # Stripe Live Secret Key
    r'''sk_test_[0-9a-zA-Z]{24}''',                            # Stripe Test Secret Key
    r'''sq0atp-[0-9A-Za-z\-_]{22}''',                         # Square Access Token
    r'''sq0csp-[0-9A-Za-z\-_]{43}''',                         # Square OAuth Secret
    r'''sq0cp-[0-9A-Za-z\-_]{31}''',                          # Square Application ID
    r'''sq0[a-z]p-[0-9A-Za-z\-_]{53}''',                      # Square Location ID
    r'''eyr[a-z0-9]{2,}'(?:&|$)''',                           # Auth0 Refresh Token
    r'''(access|refresh)_token.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,1024}.(id_token|access_token|refresh_token)''',  # OAuth Token
    r'''Bearer.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,512}''',         # OAuth Bearer Token
    r'''(consumer|api|application|access)_key.[a-zA-Z0-9\-\_\"\'\\\/\+\=]{1,512}''',  # Generic API Key
    r'''[0-9]{3}-[0-9]{2}-[0-9]{4}''',                         # Social Security Number
    r'''[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}''',               # Credit Card Number
    r'''(?!^0+$)[0-9]{3,4}''',                                # CVV Code
    r'''([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})'''  # Email Address
    r'''(\+\d{1,2}\s?)?(\d{3}|\(\d{3}\))([-.\s]?)\d{3}([-.\s]?)\d{4}''' #phone number
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
    #extract_link_from_xml()
    sub = search_subdomains(target_domain)
    get_subdomains(sub)
    print(url_to_request)

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