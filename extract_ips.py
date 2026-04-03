import re

# Read log file
with open("sample_logs.txt", "r") as file:
    logs = file.read()

# Regex to extract IP addresses
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ips = re.findall(ip_pattern, logs)

# Remove duplicates
unique_ips = list(set(ips))

print("Extracted IPs:")
for ip in unique_ips:
    print(ip)