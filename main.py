from urllib.parse import urlparse,urljoin
import requests
import re
import json
from outils.user_agents import read_user_agents, get_random_user_agent
from tqdm import tqdm

requested_url = []
to_request = []

# Liste d'User-Agents lus à partir du fichier
user_agents = read_user_agents('outils/data/user_agents.txt')
headers = {'User-Agent': get_random_user_agent(user_agents)}

def is_same_domain(url):
    # Vérifie si l'URL appartient au domaine cible
    parsed_url = urlparse(url)
    return parsed_url.netloc == target_domain

def get_header_link_data(url):
    requested_url.append(url)
    print(url)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        link_header = response.headers.get('Link')
        return link_header
    else: 
        print("can't get Link data", response.status_code)


def extract_url_in_link_data(data, base_url):
    new_links = set()
    try:
        base_url = base_url.rstrip('/')
        matches = re.finditer(r'<([^>]+)>', data)
        for match in matches:
            url = match.group(1)
            full_url = urljoin(base_url, url)
            #new_links.add(full_url)
            if is_same_domain(full_url):
                new_links.add(full_url)
        return new_links
    except Exception as e:
        print("Error:", e)
        return new_links

def get_header_data_and_extract_url(url):
    data = get_header_link_data(url)
    print(data)
    links = extract_url_in_link_data(data, url)
    for link in links:
        to_request.append(link)

def write_links_to_file(filename, links):
    with open(filename, 'a') as file:
        for link in links:
            file.write(link + '\n')

def request_loop_to_found_url():
    while len(to_request) > 0:
        links_to_process = to_request.copy()
        for link in links_to_process:
            if link not in requested_url:
                print("Récupération des données de", link)
                new_links = request_to_found_new_url(link)
                print("Requêtes restantes:", len(to_request), "Faites:", len(requested_url))
                for new_link in new_links:
                    if new_link not in requested_url and new_link not in to_request:
                        to_request.append(new_link)
                        write_links_to_file('to_request.txt', [new_link])
                requested_url.append(link)
                to_request.remove(link)
                
                # Analyser le contenu de la page à la recherche de la clé API
                response = requests.get(link, headers=headers)
                if response.status_code == 200:
                    analyze_page_content(link, response.text)
                    # Enregistrer le lien avec le code d'état dans le fichier 'requested.txt'
                    write_links_to_file('requested.txt', [f"{link} - Status Code: {response.status_code}"])
                else:
                    # En cas d'échec de la requête, enregistrer le lien avec le code d'erreur
                    write_links_to_file('requested.txt', [f"{link} - Status Code: {response.status_code}"])



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

def analyze_page_content(url, content):
    # Analyser le contenu de la page à la recherche de la clé API
    api_key = search_api_key_in_page(content)

    if api_key:
        #print(f"Clé API trouvée sur la page {url}: {api_key}")
        # Faites ce que vous devez faire avec la clé API, par exemple, l'enregistrer dans un fichier
        with open('api_keys.txt', 'a') as api_file:
            api_file.write(f"{api_key} {url}\n")

def request_to_found_new_url(url):
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        try:
            contenu_json = response.json()
            liens = []
            
            def is_valid_url(url):
                parsed_url = urlparse(url)
                return parsed_url.netloc == target_domain
            
            def explorer_json(obj):
                if isinstance(obj, list):
                    for item in obj:
                        explorer_json(item)
                elif isinstance(obj, dict):
                    for key, value in obj.items():
                        if key == 'href' or key == 'src' and isinstance(value, str) and is_same_domain(value) and is_valid_url(value):
                            liens.append(value)
                        elif isinstance(value, (list, dict)):
                            explorer_json(value)
            
            explorer_json(contenu_json)
            return liens
        except json.decoder.JSONDecodeError:
            return []
    else:
        return []
    

def main():
    global target_domain
    target_domain = "zone01rouennormandie.org"
    url = "https://" + target_domain
    
    get_header_data_and_extract_url(url)
    request_loop_to_found_url()
    
if __name__ == "__main__":
    main()