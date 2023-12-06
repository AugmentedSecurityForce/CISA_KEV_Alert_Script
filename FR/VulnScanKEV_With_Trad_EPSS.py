import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator
import csv
import gzip
from io import StringIO
import io

# URL du JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# URL du fichier EPSS
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

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

# Fonction pour récupérer le score EPSS d'une CVE
def get_epss_score(cve_id, epss_data):
    for row in epss_data:
        if row[0] == cve_id:
            return float(row[1]) * 100  # Le score EPSS est déjà entre 0 et 1
    return None

# Fonction principale
def main():
    # Récupérer le JSON depuis l'URL
    response = requests.get(url)
    json_data = response.json()

    # Récupérer le fichier EPSS
    epss_response = requests.get(epss_url)
    if epss_response.status_code == 200:
        with gzip.open(io.BytesIO(epss_response.content), 'rt', encoding='utf-8') as f:
            epss_data = list(csv.reader(f, delimiter=','))
            epss_data = epss_data[1:]  # Ignorer la première ligne du fichier EPSS

            # Obtenir les vulnérabilités de la veille
            vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

            # Afficher les informations des vulnérabilités
            for vulnerability in vulnerabilities_from_yesterday:
                cve_id = vulnerability['cveID']
                print(f"CVE ID: {cve_id}")
                
                # Récupérer et afficher le score EPSS
                epss_score = get_epss_score(cve_id, epss_data)
                if epss_score is not None:
                    print(f"EPSS Score (Probabilité d'exploitation): {epss_score}%")

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
                cvss_metrics = get_cvss_information(cve_id)
                if cvss_metrics:
                    print("\nCVSS Metrics:")
                    for metric in cvss_metrics:
                        print(f"  - {metric.get('format', '')}: {metric.get('cvssV3_1', {}).get('baseScore', '')}")
                print("\n" + "="*50 + "\n")

    else:
        print(f"Failed to retrieve EPSS data. Status code: {epss_response.status_code}")

if __name__ == "__main__":
    main()
