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
        if page.url not in url_requested and page.url not in url_to_request:
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
            if link not in u and '*' not in link:
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
                if link not in url_to_request and link not in url_requested:
                    url_to_request.append(full_url)
                    all_urls.append(full_url)
    except Exception as e:
        pass

#---------------------------------------------------------------------- 
def get_data_from_url(link):
    url = "http://" + link
    url_requested.append(link)
    if is_subdomain(url):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Lèvera une exception pour les erreurs HTTP (4xx, 5xx)
            get_header_link_data(response)
            print(url_to_request)
            # Continuez votre logique de traitement des données...
        except ConnectionError as ce:
            pass
        except requests.exceptions.RequestException as e:
            pass


            
        #print(url_to_request)
        #if response.status_code == 200:
        #    try: 
        #        contenu_json = response.json()
        #        liens = []
        #        explorer_json(contenu_json, liens, "http://" + target_domain)
        #    except json.decoder.JSONDecodeError:
        #        explorer_html(response.text)
        #except ConnectionError as ce:
        #    print(f"Erreur de connexion pour l'URL {url}")
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
        if url not in url_to_request and url not in url_requested:
            url_to_request.append(url)
            all_urls.append(url)

def explorer_json(obj, liens, target_domain):
    if isinstance(obj, list):
        for item in obj:
            explorer_json(item, liens, target_domain)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key in ('href', 'src') and isinstance(value, str) and value not in url_to_request and value not in url_requested:
                url_to_request.append(value)
                all_urls.append(value)
            elif isinstance(value, (list, dict)):
                explorer_json(value, liens, target_domain)

#----------------------------------------------------------------------
def main():
    global target_domain
    target_domain = input("Veuillez entrer l'url a target : ")
    #get_data_from_url(target_domain)
    url_to_request.append(target_domain)
    #extract_link_from_xml()

    get_subdomains()
    write_links_to_file("found_xml.txt", url_to_request)
    while len(url_to_request) > 0:
        links_to_process = url_to_request.copy()
        for link in links_to_process:
            if link not in url_requested:
                url_to_request.remove(link)
                get_data_from_url(link)
                
        print(len(url_to_request), len(url_requested))     
    
if __name__ == "__main__":
    main()