import requests
import re
import csv
import time

API_KEY = "api_key_here"

# Function to check IP using VirusTotal
def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error for IP {ip}: {response.status_code}")
        return None

# Function to classify IP with reason
def classify_ip(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return "Malicious", f"{malicious} engines flagged"
    elif suspicious > 0:
        return "Suspicious", f"{suspicious} engines flagged"
    else:
        return "Safe", "No engines flagged"

# Extract IPs from file
with open("sample_logs.txt", "r") as file:
    logs = file.read()

ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ips = re.findall(ip_pattern, logs)
unique_ips = list(set(ips))

# Counters for summary
safe_count = 0
suspicious_count = 0
malicious_count = 0

results = []

print("\n🔍 Checking IPs...\n")

for ip in unique_ips:
    print(f"Checking {ip}...")

    result = check_ip(ip)

    if result:
        stats = result["data"]["attributes"]["last_analysis_stats"]
        category, reason = classify_ip(stats)

        print(f"{ip} → {category} ({reason})")

        # Count categories
        if category == "Safe":
            safe_count += 1
        elif category == "Suspicious":
            suspicious_count += 1
        elif category == "Malicious":
            malicious_count += 1

        # Save results
        results.append([
            ip,
            category,
            reason,
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            stats.get("harmless", 0)
        ])

    else:
        print(f"{ip} → Error")
        results.append([ip, "Error", "-", "-", "-", "-"])

    print("-" * 50)

    time.sleep(15)  # API rate limit

# Print Summary
print("\n Summary Report")
print("---------------------------")
print(f"Total IPs Checked: {len(unique_ips)}")
print(f"Safe: {safe_count}")
print(f"Suspicious: {suspicious_count}")
print(f"Malicious: {malicious_count}")

# Save to CSV
with open("report.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "IP Address",
        "Category",
        "Reason",
        "Malicious Count",
        "Suspicious Count",
        "Harmless Count"
    ])

    writer.writerows(results)

print("\n Report saved as report.csv")