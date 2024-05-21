# CVE Threat Analysis Script

## Overview

This Python script fetches CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) and maps each CVE to predefined threat categories based on keywords found in the CVE descriptions. It then calculates statistics on these threats and generates visualizations of the threat percentages and their yearly evolution.


## Prerequisites

To run this script, you need the following Python packages:

- `pandas`
- `requests`
- `matplotlib`

You can install these packages using pip:

```sh
pip install pandas requests matplotlib
```

## Script Description

The script performs the following steps:

- Define Mappings: Maps threat categories and keywords to threat IDs.
- Fetch CVE Data: Retrieves CVE data from the NVD API.
- Map Threats: Maps CVE descriptions to threat IDs based on predefined keywords.
- Data Processing: Creates a DataFrame of the mapped data and calculates threat statistics.
- Visualization: Generates bar charts to visualize threat percentages and their yearly evolution.

## Data Sources

The categories and threats were extracted from the EMB3D™ Device Properties list, availabl [Here](https://emb3d.mitre.org/properties-list/).

## Running the Script

- Make sure you have the required Python packages installed.
- Run the script in your preferred Python environment.

```sh
git clone https://github.com/PaulGG-Code/EMB3D-threat_analysis.git
cd EMB3D-threat_analysis
python emb3d_cve_threat_analysis.py
```

## Output

The script will output the following:

- Threat Statistics: A DataFrame showing the percentage of each threat.
- Visualizations:
  - A bar chart showing the percentage of each threat.
  - A bar chart showing the yearly evolution of threats.

## Author
PaulGG-code 2024
