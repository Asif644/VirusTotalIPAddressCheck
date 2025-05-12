import subprocess
import json
import os
import requests
from time import sleep

VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    print("Set your VirusTotal API key in the environment variable VT_API_KEY")
    exit(1)

def extract_ips_from_pcap(pcap_file):
    cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.dst", "-e", "ip.src"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = result.stdout.strip().split('\n')
    ips = set()
    for line in lines:
        for ip in line.split():
            if ip:
                ips.add(ip)
    return sorted(ips)

def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return ip, score
    else:
        return ip, {"error": f"Status {response.status_code}"}

def main():
    pcap_file = "test.pcap"  # Change to your file name
    print(f"[+] Extracting IPs from {pcap_file}...")
    ip_list = extract_ips_from_pcap(pcap_file)
    print(f"[+] Found {len(ip_list)} unique IPs")

    print("[+] Querying VirusTotal...")
    for ip in ip_list:
        ip, result = query_virustotal(ip)
        print(f"{ip}: {result}")
        sleep(15)  # Respect rate limits on free tier

if __name__ == "__main__":
    main()

