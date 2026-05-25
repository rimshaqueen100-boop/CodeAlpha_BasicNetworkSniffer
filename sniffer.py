from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    # 1. Check if the packet has an IP Layer (Network Layer)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_name = "UNKNOWN"
        payload_preview = "None"

        # 2. Identify the Transport Layer Protocol
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"

        # 3. Extract the Payload (Application Layer Data) if it exists
        if packet.haslayer(Raw):
            # Convert raw bytes into a readable string format, replacing non-printable characters
            raw_data = packet[Raw].load
            payload_preview = raw_data[:50].decode('utf-8', errors='replace').replace('\n', ' ')
            if len(raw_data) > 50:
                payload_preview += "..."

        # 4. Print the analyzed structure clearly to the console
        print("-" * 80)
        print(f"[+] Protocol: {protocol_name}")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Payload Snippet: {payload_preview}")

print("=" * 80)
print("Starting CodeAlpha Advanced Network Sniffer... (Press Ctrl+C to stop)")
print("=" * 80)

# Sniff continuously (removed count limit) and filter for standard IP traffic
sniff(prn=packet_callback, filter="ip", store=0)