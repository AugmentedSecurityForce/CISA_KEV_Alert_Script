import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator

# JSON URL
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# EPSS file URL
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# SMTP server parameters
smtp_server = 'your_smtp_server.com'
smtp_port = 587
smtp_username = 'your_username'
smtp_password = 'your_password'

# Sender and recipients email addresses
from_address = 'your_email@example.com'
to_address = 'recipient_email@example.com'

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

# Function to get CVSS information for a CVE
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

# Function to get EPSS score
def get_epss_score(cve_id):
    epss_response = requests.get(epss_url)
    
    if epss_response.status_code == 200:
        with open('epss_scores.csv', 'wb') as f:
            f.write(epss_response.content)
            
        # Read the CSV file
        with open('epss_scores.csv', 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Ignore the first line
                values = line.strip().split(',')
                if values[0] == cve_id:
                    return float(values[1]) * 100  # Convert EPSS score to percentage
        return None
    else:
        print(f"Failed to retrieve EPSS scores. Status code: {epss_response.status_code}")
        return None

# Function to create HTML table of vulnerabilities
def create_table_html(vulnerabilities):
    table_html = "<table border='1'><tr><th>CVE ID</th><th>EPSS Score</th><th>Vendor/Project</th><th>Product</th><th>Vulnerability Name</th><th>Date Added</th><th>Short Description</th><th>Required Action</th><th>Due Date</th><th>Known Ransomware Campaign Use</th><th>Notes</th></tr>"
    for vulnerability in vulnerabilities:
        table_html += f"<tr><td>{vulnerability['cveID']}</td><td>{get_epss_score(vulnerability['cveID'])}</td><td>{vulnerability['vendorProject']}</td><td>{vulnerability['product']}</td><td>{translate_to_french(vulnerability['vulnerabilityName'])}</td><td>{vulnerability['dateAdded']}</td><td>{translate_to_french(vulnerability['shortDescription'])}</td><td>{translate_to_french(vulnerability['requiredAction'])}</td><td>{vulnerability['dueDate']}</td><td>{translate_to_french(vulnerability['knownRansomwareCampaignUse'])}</td><td>{translate_to_french(vulnerability['notes'])}</td></tr>"
    table_html += "</table>"
    return table_html

# Function to send an email
def send_email(vulnerabilities):
    # Email subject and body
    subject = 'Nouvelle(s) vulnérabilité(s) connue(s) pour exploitation'
    body = """\
    <p>Bonjour,</p>
    <p>Voici les nouvelles vulnérabilités qui ont été exploitées dans la nature. Nous vous recommandons d'en tenir compte dans le cadre de la priorisation de la gestion des vulnérabilités de votre parc.</p>
    {}
    <p>Cordialement,</p>
    """.format(create_table_html(vulnerabilities))

    # Create HTML format email
    message = MIMEMultipart()
    message.attach(MIMEText(body, 'html'))
    message['Subject'] = subject
    message['From'] = from_address
    message['To'] = to_address

    # Connect to SMTP server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send email
        server.sendmail(from_address, to_address, message.as_string())
        
        print("E-mail sent successfully!")

# Main function
def main():
    # Get JSON from the URL
    response = requests.get(url)
    json_data = response.json()

    # Check if the request was successful
    if response.status_code == 200:
        # Get vulnerabilities from yesterday
        vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

        # Check if there are new vulnerabilities
        if vulnerabilities_from_yesterday:
            # Display vulnerability information
            for vulnerability in vulnerabilities_from_yesterday:
                print(f"CVE ID: {vulnerability['cveID']}")
                print(f"EPSS Score (Probabilité d'exploitation): {get_epss_score(vulnerability['cveID'])}")
                # ...

            # Send email
            send_email(vulnerabilities_from_yesterday)

        else:
            print("No new vulnerabilities to report.")

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    main()
