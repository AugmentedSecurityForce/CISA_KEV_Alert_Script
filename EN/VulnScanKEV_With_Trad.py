import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator

# URL of the JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Function to translate fields to French
def translate_to_french(text):
    translator = GoogleTranslator(source='en', target='fr')
    translation = translator.translate(text)
    return translation

# Function to get vulnerabilities from yesterday
def get_vulnerabilities_from_yesterday(json_data):
    yesterday = datetime.now() - timedelta(days=1)
    yesterday_str = yesterday.strftime("%Y-%m-%d")

    # Filter vulnerabilities from yesterday
    vulnerabilities = [vuln for vuln in json_data['vulnerabilities'] if vuln['dateAdded'] == yesterday_str]

    return vulnerabilities

# Function to get CVE information
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

# Main function
def main():
    # Get JSON from the URL
    response = requests.get(url)
    json_data = response.json()

    # Check if the request was successful
    if response.status_code == 200:
        # Get vulnerabilities from yesterday
        vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

        # Display vulnerability information
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

            # Get CVSS information
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
