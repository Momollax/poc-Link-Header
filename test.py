from crtsh import crtshAPI
import requests

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:115.0) Gecko/20100101 Firefox/115.0"
}
def find_subdomains_passive(domain):
    subdomains = set()

    # Interroger la base de données CRT.sh pour les sous-domaines
    try:
        results = crtshAPI().search(f"%.{domain}")
        for result in results:
            subdomains.add(result['name_value'])
    except Exception as e:
        print(f"Erreur lors de la recherche passive : {e}")

    return list(subdomains)

if __name__ == "__main__":
    target_domain = "koodsisu.fi"
    found_subdomains = find_subdomains_passive(target_domain)

for subdomain in found_subdomains:
    # Ajouter le schéma "https://" au sous-domaine
    full_url = f"https://{subdomain}"

    try:
        response = requests.get(full_url, headers=headers)
        if response.status_code == 200:
            print(full_url)
        else:
            continue
    except requests.exceptions.RequestException as e:
        #print(f"Erreur lors de la requête vers {full_url}: {e}")
        continue
    else:
        continue
        #print(f"Aucun sous-domaine trouvé pour {target_domain}.")
