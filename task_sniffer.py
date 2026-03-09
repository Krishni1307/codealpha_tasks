from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "Other"

        print(f"Source: {src} | Destination: {dst} | Protocol: {proto}")

print("Starting Packet Sniffer... Press Ctrl+C to stop")
sniff(prn=packet_callback, store=0)