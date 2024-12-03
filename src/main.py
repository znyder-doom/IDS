from scapy.all import sniff
from analysis import analyze_packet
from detection import load_signatures, check_signatures

def main():
    signatures = load_signatures()  # Load known attack signatures

    def process_packet(packet):
        analyze_packet(packet)  # Analyze the packet
        check_signatures(packet, signatures)  # Check against signatures

    print("Starting IDS...")  # Inform user
    sniff(prn=process_packet, store=0)  # Capture packets and process them

if __name__ == "__main__":
    main()  # Run the main function
