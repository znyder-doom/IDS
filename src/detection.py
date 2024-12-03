import json  # For reading attack patterns from a file
from scapy.layers.inet import IP

def load_signatures():
    with open("signatures/known_attacks.json", "r") as f:  # Open the signature file
        return json.load(f)  # Load it as a Python dictionary

def check_signatures(packet, signatures):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        ip = packet[IP].src  # Get the source IP
        if ip in signatures["malicious_ips"]:  # Compare against known bad IPs
            print(f"ALERT! Malicious IP detected: {ip}")  # Alert the user
