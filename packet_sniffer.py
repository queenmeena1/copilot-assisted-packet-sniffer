from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw
from datetime import datetime
import re


# Only interfaces listed here may be used.
ALLOWED_INTERFACES = {"Wi-Fi"}

# Assignment requirement: capture 25 packets.
PACKET_COUNT = 25

# Capture only TCP or UDP traffic.
BPF_FILTER = "tcp or udp"


def redact_email(text):
    """Replace email addresses with a safe placeholder."""
    return re.sub(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        '[REDACTED_EMAIL]',
        text
    )


def redact_sensitive_values(text):
    """Redact common credentials and session information."""
    patterns = [
        r'(?i)(authorization\s*:\s*)([^\s]+)',
        r'(?i)(cookie\s*:\s*)([^\r\n]+)',
        r'(?i)(password\s*=\s*)([^&\s]+)',
        r'(?i)(token\s*=\s*)([^&\s]+)',
        r'(?i)(session[_-]?token\s*=\s*)([^&\s]+)',
    ]

    for pattern in patterns:
        text = re.sub(
            pattern,
            r'\1[REDACTED]',
            text
        )

    return text


def mask_ip(ip_address):
    """Partially mask IPv4 addresses."""
    if "." in ip_address:
        parts = ip_address.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"

    # Partially mask IPv6 addresses.
    if ":" in ip_address:
        parts = ip_address.split(":")
        return ":".join(parts[:4]) + ":xxxx"

    return "[REDACTED_IP]"


def redact_text(text):
    """Apply all required text redaction rules."""
    text = redact_email(text)
    text = redact_sensitive_values(text)
    return text


def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Get IPv4 or IPv6 addresses.
    if IP in packet:
        source = mask_ip(packet[IP].src)
        destination = mask_ip(packet[IP].dst)

    elif IPv6 in packet:
        source = mask_ip(packet[IPv6].src)
        destination = mask_ip(packet[IPv6].dst)

    else:
        return

    # Identify transport protocol.
    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    else:
        protocol = "Other"

    print(
        f"[{timestamp}] "
        f"{source} -> {destination} | {protocol}"
    )

    # Decode DNS queries.
    if DNS in packet and packet[DNS].qd is not None:
        try:
            query = packet[DNSQR].qname.decode(
                "utf-8",
                errors="ignore"
            )
            query = redact_text(query)
            print(f"    DNS Query: {query}")
        except Exception:
            pass

    # Inspect HTTP-like payloads without displaying sensitive values.
    if Raw in packet and TCP in packet:
        try:
            payload = packet[Raw].load.decode(
                "utf-8",
                errors="ignore"
            )

            if (
                payload.startswith("GET ")
                or payload.startswith("POST ")
                or "Host:" in payload
                or "Authorization:" in payload
                or "Cookie:" in payload
            ):
                safe_payload = redact_text(payload)

                # Avoid printing the entire payload.
                first_line = safe_payload.splitlines()[0]
                print(f"    HTTP: {first_line}")

        except Exception:
            pass


def main():
    interface = "Wi-Fi"

    if interface not in ALLOWED_INTERFACES:
        raise ValueError(
            f"Interface '{interface}' is not authorized."
        )

    print("Authorized Packet Sniffer")
    print(f"Interface: {interface}")
    print(f"Filter: {BPF_FILTER}")
    print(f"Packet limit: {PACKET_COUNT}")
    print("Sensitive information will be redacted.")
    print("Press CTRL+C to stop.")
    print("-" * 60)

    sniff(
        iface=interface,
        filter=BPF_FILTER,
        prn=process_packet,
        count=PACKET_COUNT,
        store=False
    )


if __name__ == "__main__":
    main()