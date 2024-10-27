from scapy.all import sniff, Ether, IP

# Function to process each packet
def packet_handler(packet):
    if packet.haslayer(Ether):
        print("\nEthernet Frame:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")

    # Check if the packet contains an IP layer
    if packet.haslayer(IP):
        print("IP Packet:")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  TTL: {packet[IP].ttl}")

# Start sniffing packets
print("Starting packet sniffing... Press Ctrl+C to stop.")
try:
    sniff(prn=packet_handler, filter="ip", store=0)  # filter="ip" to capture only IP packets
except KeyboardInterrupt:
    print("\nPacket sniffing stopped.")
