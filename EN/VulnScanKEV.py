import requests
from datetime import datetime, timedelta

# URL of the JSON
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Function to get vulnerabilities from yesterday
def get_vulnerabilities_from_yesterday(json_data):
    yesterday = datetime.now() - timedelta(days=1)
    yesterday_str = yesterday.strftime("%Y-%m-%d")

    # Filter vulnerabilities from yesterday
    vulnerabilities = [vuln for vuln in json_data['vulnerabilities'] if vuln['dateAdded'] == yesterday_str]

    return vulnerabilities

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
            print(f"Vulnerability Name: {vulnerability['vulnerabilityName']}")
            print(f"Date Added: {vulnerability['dateAdded']}")
            print(f"Short Description: {vulnerability['shortDescription']}")
            print(f"Required Action: {vulnerability['requiredAction']}")
            print(f"Due Date: {vulnerability['dueDate']}")
            print(f"Known Ransomware Campaign Use: {vulnerability['knownRansomwareCampaignUse']}")
            print(f"Notes: {vulnerability['notes']}")
            print("\n" + "="*50 + "\n")

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    main()
