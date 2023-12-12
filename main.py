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
        if page.url not in url_to_request:
            url_to_request.append(page.url)
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
            if link not in u and '*' not in link:
                url_to_request.append(link)
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
                if link not in url_to_request:
                    
                    url_to_request.append(full_url)

    except Exception as e:
        pass

#---------------------------------------------------------------------- 
def analyze_page_content(url, content):
    # Analyser le contenu de la page à la recherche de la clé API
    api_key = search_api_key_in_page(content)

    if api_key:
        #print(f"Clé API trouvée sur la page {url}: {api_key}")
        # Faites ce que vous devez faire avec la clé API, par exemple, l'enregistrer dans un fichier
        with open('api_keys.txt', 'a') as api_file:
            api_file.write(f"{api_key} {url}\n")

def search_api_key_in_page(content):
    api_key_patterns = [
    r'-----BEGIN RSA PRIVATE KEY-----',                                                                 # RSA private key
    r'-----BEGIN DSA PRIVATE KEY-----',                                                                 # SSH (DSA) private key
    r'-----BEGIN EC PRIVATE KEY-----',                                                                  # SSH (EC) private key
    r'-----BEGIN PGP PRIVATE KEY BLOCK-----',                                                           # PGP private key block
    r'AKIA[0-9A-Z]{16}',                                                                                # Amazon AWS Access Key ID
    r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',                         # Amazon MWS Auth Token
    r'AKIA[0-9A-Z]{16}',                                                                                # AWS API Key
    r'[g|G][i|I][t|T][h|H][u|U][b|B].*[\'|\"][0-9a-zA-Z]{35,40}[\'|\"]',                                # GitHub
    r'AIza[0-9A-Za-z\\-_]{35}',                                                                         # Google API Key
    r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',                                           # Google YouTube OAuth
    r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',    # Heroku API Key
    r'[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}["\'\\s]',                               # Password in URL
    r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',             # Slack Webhook
    r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',                                # Twitter Access Token
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
                print("error regex")

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
                    write_links_to_file_append('requested_json.txt', [f"{link} - Status Code: {response.status_code}"])
                except json.decoder.JSONDecodeError:
                    explorer_html(response.text)
                    analyze_page_content(link, response.text)
                    write_links_to_file_append('requested_html.txt', [f"{link} - Status Code: {response.status_code}"])
            else:
                write_links_to_file_append('requested_error.txt', [f"{link} - Status Code: {response.status_code}"])
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
        if url not in url_to_request :
            url_to_request.append(url)

def explorer_json(obj, liens, target_domain):
    if isinstance(obj, list):
        for item in obj:
            explorer_json(item, liens, target_domain)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key in ('href', 'src') and isinstance(value, str) and value not in url_to_request:
                url_to_request.append(value)
            elif isinstance(value, (list, dict)):
                explorer_json(value, liens, target_domain)

#----------------------------------------------------------------------
def main():
    global target_domain

    target_domain = input("Veuillez entrer l'url a target : ")
    url_to_request.append(target_domain)
    extract_link_from_xml()
    get_subdomains()
    while len(url_to_request) > 0:
        links_to_process = url_to_request.copy()
        for link in links_to_process:
            if link not in url_requested:
                url_to_request.remove(link)
                get_data_from_url(link)
                write_links_to_file("url_requested.txt", url_requested)   
                write_links_to_file("url_to_request.txt", url_to_request)   
    
if __name__ == "__main__":
    main()