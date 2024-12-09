import re
import json
import csv
from collections import defaultdict
log_file = 'server_logs.txt'
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) /login HTTP/1.1" (\d+) (\d+)'
uğursuz_giriş = defaultdict(int)
log_data = []
with open(log_file, 'r') as f:
    for line in f:
        match = re.search(log_pattern, line)
        if match:
            ip = match.group(1)
            tarix = match.group(2)
            metod = match.group(3)
            status_kodu = match.group(4)
            ölçüsü = match.group(5)
            log_data.append({'IP': ip, 'Tarix': tarix, 'Metod': metod, 'Status': status_kodu})
            if status_kodu == '401':
                uğursuz_giriş[ip] += 1
uğursuz_giriş_ip = {ip: count for ip, count in uğursuz_giriş.items() if count > 5}
with open('failed_logins.json', 'w') as f:
    json.dump(uğursuz_giriş_ip, f, indent=4)
threat_ips = ['192.168.1.11',]
threat_ip_data = [entry for entry in log_data if entry['IP'] in threat_ips]

with open('threat_ips.json', 'w') as f:
    json.dump([entry['IP'] for entry in threat_ip_data], f, indent=4)
combined_security_data = {
    'failed_logins': uğursuz_giriş_ip,
    'threat_ips': [entry['IP'] for entry in threat_ip_data]
}

with open('combined_security_data.json', 'w') as f:
    json.dump(combined_security_data, f, indent=4)
with open('log_analysis.txt', 'w') as f:
    for ip, count in uğursuz_giriş_ip.items():
        f.write(f"{ip} failed {count} login attempts\n")
with open('log_analysis.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Tarix', 'Metod', 'Status']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for entry in log_data:
        writer.writerow(entry)

print("Bütün əməliyyatlar yerinə yetirildi")