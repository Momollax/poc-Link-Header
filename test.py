import requests

def get_subdomains(domain):
    url = f'https://crt.sh/?q=%.{domain}&output=json'
    try:
        response = requests.get(url)
        data = response.json()
        subdomains = set()
        for entry in data:
            subdomain = entry['name_value'].strip()
            subdomains.add(subdomain)
        return subdomains
    except Exception as e:
        print(f"Erreur lors de la récupération des sous-domaines : {e}")
        return set()

if __name__ == "__main__":
    target_domain = "snowpack.eu"
    subdomains = get_subdomains(target_domain)

    if subdomains:
        print(f"Sous-domaines de {target_domain} :")
        for subdomain in subdomains:
            print(subdomain)
    else:
        print(f"Aucun sous-domaine trouvé pour {target_domain}.")