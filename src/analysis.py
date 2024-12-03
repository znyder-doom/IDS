from scapy.all import IP, TCP  # Import layers for analysis

def analyze_packet(packet):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        ip_layer = packet.getlayer(IP)  # Extract the IP layer
        print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")  # Print IPs

    if packet.haslayer(TCP):  # Check if the packet has a TCP layer
        tcp_layer = packet.getlayer(TCP)  # Extract the TCP layer
        print(f"Source Port: {tcp_layer.sport}, Dest Port: {tcp_layer.dport}")  # Print ports
