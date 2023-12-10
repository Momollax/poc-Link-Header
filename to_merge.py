from usp.tree import sitemap_tree_for_homepage
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_resources(page_content, base_url):
    soup = BeautifulSoup(page_content, 'html.parser')

    links = set()
    scripts = set()
    stylesheets = set()

    # Extraire les liens <a>
    links.update(urljoin(base_url, a['href']) for a in soup.find_all('a', href=True))

    # Extraire les balises <script>
    scripts.update(urljoin(base_url, script['src']) for script in soup.find_all('script', src=True))

    # Extraire les balises <link> avec rel="stylesheet"
    stylesheets.update(urljoin(base_url, link['href']) for link in soup.find_all('link', rel='stylesheet', href=True))

    # Vous pouvez ajouter d'autres types de ressources ici selon vos besoins

    return links, scripts, stylesheets

def print_resources(resource_type, resources):
    return f"{resource_type.capitalize()}:\n" + '\n'.join(f"  - {resource}" for resource in resources)

def save_to_file(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(data)
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier {filename}: {e}")


tree = sitemap_tree_for_homepage('https://snowpack.eu')

requested = set()
to_request = set()
all_resources = set()

# all_pages() retourne un itérateur
for page in tree.all_pages():
    if page.url not in requested:
        response = requests.get(page.url)

        if response.status_code == 200:
            links, scripts, stylesheets = extract_resources(response.text, page.url)

            print(f"\nPage: {page.url}")
            print(print_resources("Liens", links))
            print(print_resources("Scripts", scripts))
            print(print_resources("Stylesheets", stylesheets))

            requested.add(page.url)  # Ajouter l'URL à la liste des demandes effectuées

            # Ajouter les nouveaux liens à la liste des demandes à effectuer
            to_request.update(links)
            to_request.update(scripts)
            to_request.update(stylesheets)

            # Ajouter tous les liens à l'ensemble global
            all_resources.update(links)
            all_resources.update(scripts)
            all_resources.update(stylesheets)

            # Écrire les URLs demandées dans un fichier en temps réel
            save_to_file('requested.txt', '\n'.join(requested))

            # Écrire les URLs à requêter dans un fichier en temps réel
            save_to_file('to_request.txt', '\n'.join(to_request))

            # Écrire tous les liens dans un fichier en temps réel
            save_to_file('all_resources.txt', '\n'.join(all_resources))

# Vous pouvez également stocker ces liens dans une liste si vous en avez besoin
urls = [page.url for page in tree.all_pages()]
print(len(urls), urls[0:2])

# Afficher les URLs dans to_request qui n'ont pas encore été demandées
to_request -= requested
print("\nURLs à requêter:")
for url in to_request:
    print(f"  - {url}")
