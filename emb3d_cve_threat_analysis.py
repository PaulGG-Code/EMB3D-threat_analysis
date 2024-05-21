import pandas as pd
import requests
import matplotlib.pyplot as plt
from collections import Counter

# This script fetches CVE data from the NVD database, maps the CVEs to predefined threat categories based on keywords,
# calculates statistics on these threats, and generates visualizations of the threat percentages and their yearly evolution.

# Define the mapping of threats to categories
categories = {
    'Hardware': [
        'TID-101', 'TID-102', 'TID-103', 'TID-105', 'TID-106', 'TID-107', 'TID-108',
        'TID-109', 'TID-110', 'TID-113', 'TID-114', 'TID-111', 'TID-118', 'TID-115',
        'TID-116', 'TID-119'
    ],
    'System Software': [
        'TID-201', 'TID-224', 'TID-202', 'TID-218', 'TID-203', 'TID-204', 'TID-205',
        'TID-219', 'TID-206', 'TID-223', 'TID-207', 'TID-208', 'TID-209', 'TID-214',
        'TID-220', 'TID-210', 'TID-211', 'TID-330', 'TID-212', 'TID-213', 'TID-215',
        'TID-216', 'TID-217'
    ],
    'Application Software': [
        'TID-301', 'TID-319', 'TID-320', 'TID-321', 'TID-322', 'TID-323', 'TID-324',
        'TID-325', 'TID-326', 'TID-327', 'TID-302', 'TID-303', 'TID-304', 'TID-305',
        'TID-306', 'TID-307', 'TID-308', 'TID-309', 'TID-310', 'TID-328', 'TID-311',
        'TID-312', 'TID-313', 'TID-314', 'TID-329', 'TID-315', 'TID-316', 'TID-317',
        'TID-411', 'TID-330', 'TID-318'
    ],
    'Networking': [
        'TID-401', 'TID-310', 'TID-222', 'TID-404', 'TID-405', 'TID-407', 'TID-406',
        'TID-408', 'TID-318', 'TID-221', 'TID-410', 'TID-316', 'TID-317', 'TID-411',
        'TID-412'
    ]
}

# Define a heuristic mapping of threat IDs to keywords
keyword_mapping = {
    'TID-101': ['power', 'consumption', 'side channel'],
    'TID-102': ['electromagnetic', 'side channel'],
    'TID-103': ['cache', 'timing', 'side channel'],
    'TID-105': ['fault injection', 'control flow'],
    'TID-106': ['data bus', 'interception'],
    'TID-107': ['unauthorized', 'direct memory access'],
    'TID-108': ['ROM', 'NVRAM', 'data extraction'],
    'TID-109': ['RAM', 'chip', 'readout'],
    'TID-110': ['fault injection', 'data manipulation'],
    'TID-113': ['unverified', 'firmware'],
    'TID-114': ['peripheral', 'data bus', 'interception'],
    'TID-111': ['untrusted', 'external storage'],
    'TID-118': ['weak', 'electrical', 'damage protection'],
    'TID-115': ['firmware', 'extraction', 'hardware interface'],
    'TID-116': ['privileged access', 'port'],
    'TID-119': ['debug port', 'memory manipulation'],
    'TID-201': ['bootloader', 'protection'],
    'TID-224': ['diagnostic', 'access'],
    'TID-202': ['network stack', 'component'],
    'TID-218': ['rootkit'],
    'TID-203': ['malicious', 'kernel driver'],
    'TID-204': ['untrusted', 'privileged functions'],
    'TID-205': ['maliciously', 'existing tools'],
    'TID-219': ['privilege escalation'],
    'TID-206': ['memory management', 'subverted'],
    'TID-223': ['RAM', 'scraping'],
    'TID-207': ['container escape'],
    'TID-208': ['virtual machine escape'],
    'TID-209': ['host', 'manipulate', 'virtual machine'],
    'TID-214': ['secrets', 'root of trust'],
    'TID-220': ['unpatchable', 'hardware root of trust'],
    'TID-210': ['unpatchable', 'vulnerabilities'],
    'TID-211': ['unauthenticated', 'firmware installation'],
    'TID-330': ['cryptographic', 'side-channel'],
    'TID-212': ['integrity', 'shared secrets'],
    'TID-213': ['faulty', 'integrity verification'],
    'TID-215': ['unencrypted', 'firmware updates'],
    'TID-216': ['rollback', 'firmware update'],
    'TID-217': ['remotely', 'update', 'DoS'],
    'TID-301': ['application', 'binaries', 'modified'],
    'TID-319': ['cross site scripting', 'XSS'],
    'TID-320': ['SQL injection'],
    'TID-321': ['session hijacking'],
    'TID-322': ['cross site request forgery', 'CSRF'],
    'TID-323': ['HTTP', 'path traversal'],
    'TID-324': ['direct object reference'],
    'TID-325': ['injection', 'response splitting'],
    'TID-326': ['insecure deserialization'],
    'TID-327': ['out of bounds', 'memory access'],
    'TID-302': ['untrusted', 'application'],
    'TID-303': ['excessive trust', 'management software'],
    'TID-304': ['manipulate', 'runtime environment'],
    'TID-305': ['dangerous', 'system calls'],
    'TID-306': ['sandbox', 'escaped'],
    'TID-307': ['code representations', 'inconsistent'],
    'TID-308': ['code overwritten', 'avoid detection'],
    'TID-309': ['exploit', 'engineering workstation'],
    'TID-310': ['unauthenticated', 'services'],
    'TID-328': ['hardcoded credentials'],
    'TID-311': ['default credentials'],
    'TID-312': ['credential change', 'abuse'],
    'TID-313': ['unauthenticated', 'session changes'],
    'TID-314': ['brute-force', 'password'],
    'TID-329': ['improper password', 'storage'],
    'TID-315': ['password retrieval', 'abuse'],
    'TID-316': ['incorrect certificate', 'authentication bypass'],
    'TID-317': ['predictable', 'cryptographic key'],
    'TID-411': ['weak cryptographic', 'protocol'],
    'TID-318': ['insecure cryptographic', 'implementation'],
    'TID-401': ['undocumented protocol', 'features'],
    'TID-310': ['unauthenticated', 'remote'],
    'TID-222': ['critical system service', 'disabled'],
    'TID-404': ['triggerable', 'deadlock', 'DoS'],
    'TID-405': ['network stack', 'resource exhaustion'],
    'TID-407': ['missing', 'replay protection'],
    'TID-406': ['unauthorized', 'messages', 'connections'],
    'TID-408': ['unencrypted', 'sensitive data'],
    'TID-221': ['message replay', 'authentication bypass'],
    'TID-410': ['cryptographic protocol', 'side-channel'],
    'TID-412': ['network routing', 'abuse']
}

# Function to fetch CVEs from the NVD database
def fetch_nvd_data(start_index=0, results_per_page=2000):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    response = requests.get(url, params=params)
    try:
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        return data
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except requests.exceptions.RequestException as req_err:
        print(f'Request exception occurred: {req_err}')
    except ValueError as json_err:
        print(f'JSON decode error: {json_err}')
    return None

# Function to map CVE descriptions to threat IDs based on keywords
def map_threats(description):
    for threat, keywords in keyword_mapping.items():
        if any(keyword in description.lower() for keyword in keywords):
            return threat
    return None

# Fetch data from NVD
nvd_data = fetch_nvd_data()

if nvd_data:
    # Debug print to check the structure of the response
    print(nvd_data.keys())

    # Map fetched data to the appropriate categories and threats
    mapped_data = []
    for item in nvd_data.get('vulnerabilities', []):
        cve_id = item['cve']['id']
        description = item['cve']['descriptions'][0]['value']
        published_date = item['cve']['published'][:4]  # Extracting year from published date
        threat_id = map_threats(description)
        if threat_id:
            category = next(cat for cat, threats in categories.items() if threat_id in threats)
            mapped_data.append({
                'CVE_ID': cve_id,
                'Description': description,
                'Category': category,
                'Threat': threat_id,
                'Year': published_date
            })

    # Create a DataFrame from the mapped data
    df = pd.DataFrame(mapped_data)

    # Calculate threat counts
    threat_counts = Counter(df['Threat'])
    total_threats = sum(threat_counts.values())

    # Calculate threat percentages
    threat_percentages = {threat: (count / total_threats) * 100 for threat, count in threat_counts.items()}

    # Create a DataFrame for threat percentages
    threat_df = pd.DataFrame(list(threat_percentages.items()), columns=['Threat', 'Percentage'])

    # Display threat statistics
    print("Threat Statistics:")
    print(threat_df)

    # Plot the threat percentages
    plt.figure(figsize=(12, 8))
    plt.bar(threat_df['Threat'], threat_df['Percentage'], color='skyblue')
    plt.xlabel('Threats')
    plt.ylabel('Percentage')
    plt.title('Threat Percentages')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    # Calculate threat counts by year
    yearly_threat_counts = df.groupby('Year')['Threat'].count()

    # Plot the yearly evolution of threats
    plt.figure(figsize=(12, 8))
    yearly_threat_counts.plot(kind='bar', color='skyblue')
    plt.xlabel('Year')
    plt.ylabel('Number of Threats')
    plt.title('Yearly Evolution of Threats')
    plt.tight_layout()
    plt.show()
else:
    print("Failed to fetch data from NVD.")
