from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR
from datetime import datetime


def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
    else:
        return

    if TCP in packet:
        protocol_name = "TCP"
    elif UDP in packet:
        protocol_name = "UDP"
    else:
        protocol_name = "Other"

    print(
        f"[{timestamp}] "
        f"{source} -> {destination} | "
        f"{protocol_name}"
    )

    if DNS in packet and packet[DNS].qd is not None:
        try:
            query = packet[DNSQR].qname.decode(
                "utf-8",
                errors="ignore"
            )
            print(f"    DNS Query: {query}")
        except Exception:
            pass


print("Authorized Packet Sniffer")
print("Capturing packets... Press CTRL+C to stop.")
print("-" * 60)

sniff(iface="Wi-Fi", prn=process_packet, store=False)