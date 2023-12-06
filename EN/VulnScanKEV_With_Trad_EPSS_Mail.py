import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import gzip
import csv

# URL of the JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# URL of the EPSS file
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

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

# Function to get EPSS score for a CVE
def get_epss_score(cve_id):
    response = requests.get(epss_url)
    with open('epss_scores-current.csv.gz', 'wb') as f:
        f.write(response.content)

    with gzip.open('epss_scores-current.csv.gz', 'rt', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # Ignore the first line
        for line in reader:
            if line[0] == cve_id:
                return float(line[2]) * 100

    return None

# Function to create HTML content for the email
def create_html_content(vulnerabilities):
    content = """
    <html>
        <body>
            <p>Bonjour,</p>
            <p>Voici les nouvelles vulnérabilités qui ont été exploitées dans la nature. Nous vous recommandons d'en tenir compte dans le cadre de la priorisation de la gestion des vulnérabilités de votre parc.</p>
            <table border="1">
                <tr>
                    <th>CVE ID</th>
                    <th>EPSS Score (Probabilité d'exploitation)</th>
                    <th>Vendor/Project</th>
                    <th>Product</th>
                    <th>Vulnerability Name</th>
                    <th>Date Added</th>
                    <th>Short Description</th>
                    <th>Required Action</th>
                    <th>Due Date</th>
                    <th>Known Ransomware Campaign Use</th>
                    <th>Notes</th>
                </tr>
    """

    for vulnerability in vulnerabilities:
        epss_score = get_epss_score(vulnerability['cveID'])
        content += f"""
            <tr>
                <td>{vulnerability['cveID']}</td>
                <td>{epss_score}%</td>
                <td>{vulnerability['vendorProject']}</td>
                <td>{vulnerability['product']}</td>
                <td>{translate_to_french(vulnerability['vulnerabilityName'])}</td>
                <td>{vulnerability['dateAdded']}</td>
                <td>{translate_to_french(vulnerability['shortDescription'])}</td>
                <td>{translate_to_french(vulnerability['requiredAction'])}</td>
                <td>{vulnerability['dueDate']}</td>
                <td>{translate_to_french(vulnerability['knownRansomwareCampaignUse'])}</td>
                <td>{translate_to_french(vulnerability['notes'])}</td>
            </tr>
        """

    content += """
            </table>
            <p>Cordialement.</p>
        </body>
    </html>
    """

    return content

# Function to create the .eml file
def create_eml_file(vulnerabilities):
    msg = MIMEMultipart()
    msg['Subject'] = "Nouvelle(s) vulnérabilité(s) connue(s) pour exploitation."
    msg.attach(MIMEText(create_html_content(vulnerabilities), 'html'))

    with open('nouvelles_vulnerabilites.eml', 'w') as f:
        f.write(msg.as_string())

# Main function
def main():
    # Get JSON from the URL
    response = requests.get(url)
    json_data = response.json()

    # Check if the request was successful
    if response.status_code == 200:
        # Get vulnerabilities from yesterday
        vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

        # Create the .eml file
        create_eml_file(vulnerabilities_from_yesterday)

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    main()
