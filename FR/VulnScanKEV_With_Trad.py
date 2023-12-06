import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator

# URL du JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Fonction pour traduire les champs en français
def translate_to_french(text):
    translator = GoogleTranslator(source='en', target='fr')
    translation = translator.translate(text)
    return translation

# Fonction pour récupérer les vulnérabilités de la veille
def get_vulnerabilities_from_yesterday(json_data):
    yesterday = datetime.now() - timedelta(days=1)
    yesterday_str = yesterday.strftime("%Y-%m-%d")

    # Filtrer les vulnérabilités de la veille
    vulnerabilities = [vuln for vuln in json_data['vulnerabilities'] if vuln['dateAdded'] == yesterday_str]

    return vulnerabilities

# Fonction pour récupérer les informations CVSS d'une CVE
def get_cvss_information(cve_id):
    cvss_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(cvss_url)

    if response.status_code == 200:
        cvss_data = response.json()
        cvss_metrics = cvss_data.get('cveMetadata', {}).get('metrics', [])
        return cvss_metrics
    else:
        print(f"Failed to retrieve CVSS information for {cve_id}. Status code: {response.status_code}")
        return None

# Fonction principale
def main():
    # Récupérer le JSON depuis l'URL
    response = requests.get(url)
    json_data = response.json()

    # Vérifier si la requête a réussi
    if response.status_code == 200:
        # Obtenir les vulnérabilités de la veille
        vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

        # Afficher les informations des vulnérabilités
        for vulnerability in vulnerabilities_from_yesterday:
            print(f"CVE ID: {vulnerability['cveID']}")
            print(f"Vendor/Project: {vulnerability['vendorProject']}")
            print(f"Product: {vulnerability['product']}")
            print(f"Vulnerability Name: {translate_to_french(vulnerability['vulnerabilityName'])}")
            print(f"Date Added: {vulnerability['dateAdded']}")
            print(f"Short Description: {translate_to_french(vulnerability['shortDescription'])}")
            print(f"Required Action: {translate_to_french(vulnerability['requiredAction'])}")
            print(f"Due Date: {vulnerability['dueDate']}")
            print(f"Known Ransomware Campaign Use: {translate_to_french(vulnerability['knownRansomwareCampaignUse'])}")
            print(f"Notes: {translate_to_french(vulnerability['notes'])}")

            # Récupérer les informations CVSS
            cvss_metrics = get_cvss_information(vulnerability['cveID'])
            if cvss_metrics:
                print("\nCVSS Metrics:")
                for metric in cvss_metrics:
                    print(f"  - {metric.get('format', '')}: {metric.get('cvssV3_1', {}).get('baseScore', '')}")
            print("\n" + "="*50 + "\n")

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    main()
