# malicious-ip-intelligence-system

## Objective
This project detects malicious IP addresses using threat intelligence.

## Tools Used
- Python
- VirusTotal API

## Features
- Extracts IPs from logs
- Checks IP reputation
- Classifies (Safe / Suspicious / Malicious)
- Generates CSV report

## How to Run
1. Install dependencies:
   pip install requests

2. Add your VirusTotal API key in the script

3. Run:
   python ip_checker.py

## Output
- report.csv with classified IPs
