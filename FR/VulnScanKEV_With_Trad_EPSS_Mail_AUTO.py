import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import requests
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator

# URL du JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# URL du fichier EPSS
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Paramètres du serveur SMTP
smtp_server = 'your_smtp_server.com'
smtp_port = 587
smtp_username = 'your_username'
smtp_password = 'your_password'

# Adresse e-mail de l'expéditeur et des destinataires
from_address = 'your_email@example.com'
to_address = 'recipient_email@example.com'

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

# Fonction pour récupérer le score EPSS
def get_epss_score(cve_id):
    epss_response = requests.get(epss_url)
    
    if epss_response.status_code == 200:
        with open('epss_scores.csv', 'wb') as f:
            f.write(epss_response.content)
            
        # Lire le fichier CSV
        with open('epss_scores.csv', 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Ignorer la première ligne
                values = line.strip().split(',')
                if values[0] == cve_id:
                    return float(values[1]) * 100  # Convertir le score EPSS en pourcentage
        return None
    else:
        print(f"Failed to retrieve EPSS scores. Status code: {epss_response.status_code}")
        return None

# Fonction pour créer le tableau HTML des vulnérabilités
def create_table_html(vulnerabilities):
    table_html = "<table border='1'><tr><th>CVE ID</th><th>EPSS Score</th><th>Vendor/Project</th><th>Product</th><th>Vulnerability Name</th><th>Date Added</th><th>Short Description</th><th>Required Action</th><th>Due Date</th><th>Known Ransomware Campaign Use</th><th>Notes</th></tr>"
    for vulnerability in vulnerabilities:
        table_html += f"<tr><td>{vulnerability['cveID']}</td><td>{get_epss_score(vulnerability['cveID'])}</td><td>{vulnerability['vendorProject']}</td><td>{vulnerability['product']}</td><td>{translate_to_french(vulnerability['vulnerabilityName'])}</td><td>{vulnerability['dateAdded']}</td><td>{translate_to_french(vulnerability['shortDescription'])}</td><td>{translate_to_french(vulnerability['requiredAction'])}</td><td>{vulnerability['dueDate']}</td><td>{translate_to_french(vulnerability['knownRansomwareCampaignUse'])}</td><td>{translate_to_french(vulnerability['notes'])}</td></tr>"
    table_html += "</table>"
    return table_html

# Fonction pour envoyer un e-mail
def send_email(vulnerabilities):
    # Sujet et corps du mail
    subject = 'Nouvelle(s) vulnérabilité(s) connue(s) pour exploitation'
    body = """\
    <p>Bonjour,</p>
    <p>Voici les nouvelles vulnérabilités qui ont été exploitées dans la nature. Nous vous recommandons d'en tenir compte dans le cadre de la priorisation de la gestion des vulnérabilités de votre parc.</p>
    {}
    <p>Cordialement,</p>
    """.format(create_table_html(vulnerabilities))

    # Création de l'e-mail au format HTML
    message = MIMEMultipart()
    message.attach(MIMEText(body, 'html'))
    message['Subject'] = subject
    message['From'] = from_address
    message['To'] = to_address

    # Connexion au serveur SMTP
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Envoi de l'e-mail
        server.sendmail(from_address, to_address, message.as_string())
        
        print("E-mail envoyé avec succès!")

# Fonction principale
def main():
    # Récupérer le JSON depuis l'URL
    response = requests.get(url)
    json_data = response.json()

    # Vérifier si la requête a réussi
    if response.status_code == 200:
        # Obtenir les vulnérabilités de la veille
        vulnerabilities_from_yesterday = get_vulnerabilities_from_yesterday(json_data)

        # Vérifier s'il y a de nouvelles vulnérabilités
        if vulnerabilities_from_yesterday:
            # Afficher les informations des vulnérabilités
            for vulnerability in vulnerabilities_from_yesterday:
                print(f"CVE ID: {vulnerability['cveID']}")
                print(f"EPSS Score (Probabilité d'exploitation) : {get_epss_score(vulnerability['cveID'])}")
                # ...

            # Envoyer l'e-mail
            send_email(vulnerabilities_from_yesterday)

        else:
            print("Aucune nouvelle vulnérabilité à signaler.")

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    main()
