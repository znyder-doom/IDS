from scapy.all import sniff  # Import 'sniff' function from Scapy

def capture_packets():
    print("Starting packet capture...")  # Inform the user that capturing has started
    sniff(prn=lambda packet: print(packet.summary()), store=0)  # Capture packets

if __name__ == "__main__":
    capture_packets()  # Run the function
