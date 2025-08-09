#!/usr/bin/env python3

import argparse
import time
import atexit
from collections import defaultdict, Counter
from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, DNS, Raw, PcapWriter

# --- Global Variables for Statistics and Threat Detection ---

# Statistics tracking
stats = {
    "packet_count": 0,
    "protocols": Counter(),
    "top_talkers": Counter()
}

# ARP table for spoof detection: {"ip": "mac"}
arp_table = {}

# Port scan detection: { "dst_ip": { "src_ip": [timestamps] } }
syn_tracker = defaultdict(lambda: defaultdict(list))
PORT_SCAN_THRESHOLD = 15  # Num of SYNs from one source
PORT_SCAN_TIMEFRAME = 60  # Within this many seconds

def print_summary():
    """Prints a summary of the captured traffic upon exit."""
    print("\n--- Capture Summary ---")
    print(f"Total Packets Captured: {stats['packet_count']}")
    if not stats['protocols']:
        print("No traffic was captured.")
        return
        
    print("\nProtocol Distribution:")
    for proto, count in stats['protocols'].most_common():
        print(f"  {proto:<5}: {count} packets")
        
    print("\nTop 5 Talkers (Source IPs):")
    for ip, count in stats['top_talkers'].most_common(5):
        print(f"  {ip}: {count} packets")
    print("-----------------------\n")

def process_packet(packet):
    """
    The main callback function called by Scapy's sniff().
    It dispatches the packet to the correct processing function and updates stats.
    """
    if 'pcap_writer' in globals():
        pcap_writer.write(packet)

    stats['packet_count'] += 1

    if ARP in packet:
        stats['protocols']['ARP'] += 1
        process_arp_packet(packet)
    elif IP in packet:
        stats['top_talkers'][packet[IP].src] += 1
        process_ip_packet(packet)
    elif IPv6 in packet:
        stats['top_talkers'][packet[IPv6].src] += 1
        stats['protocols']['IPv6'] += 1
        process_ipv6_packet(packet)

def process_arp_packet(packet):
    """Detects ARP spoofing attacks."""
    if packet[ARP].op == 2:  # is-at (response)
        ip_addr, mac_addr = packet[ARP].psrc, packet[ARP].hwsrc
        if ip_addr in arp_table and arp_table[ip_addr] != mac_addr:
            print(f"\n[!] ALERT: Potential ARP Spoofing Detected!")
            print(f"    IP: {ip_addr} changed MAC from {arp_table[ip_addr]} to {mac_addr}\n")
        arp_table[ip_addr] = mac_addr

def process_ip_packet(packet):
    """Processes IPv4 packets."""
    if TCP in packet:
        stats['protocols']['TCP'] += 1
        process_tcp_packet(packet)
    elif UDP in packet:
        stats['protocols']['UDP'] += 1
        process_udp_packet(packet)
    else:
        stats['protocols']['Other_IP'] += 1

def process_tcp_packet(packet):
    """Processes TCP packets, including payload and port scan detection."""
    ip_src, ip_dst = packet[IP].src, packet[IP].dst
    tcp_sport, tcp_dport = packet[TCP].sport, packet[TCP].dport
    flags = packet[TCP].flags
    
    print(f"[*] TCP: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} | Flags: {flags}")

    # OS Fingerprinting
    ttl = packet[IP].ttl
    if ttl <= 64: os_guess = "Linux/Unix"
    elif ttl <= 128: os_guess = "Windows"
    else: os_guess = "Router/Other"
    print(f"    [i] TTL: {ttl} (Potential OS: {os_guess})")

    # Port Scan Detection
    if flags == 'S':
        current_time = time.time()
        tracker = syn_tracker[ip_dst][ip_src]
        tracker.append(current_time)
        tracker = [t for t in tracker if current_time - t < PORT_SCAN_TIMEFRAME]
        syn_tracker[ip_dst][ip_src] = tracker
        if len(tracker) >= PORT_SCAN_THRESHOLD:
            print(f"\n[!] ALERT: Potential Port Scan Detected from {ip_src} to {ip_dst}\n")
            syn_tracker[ip_dst][ip_src] = []

    # HTTP Payload check
    if Raw in packet:
        check_for_http_payload(packet)

def process_udp_packet(packet):
    """Processes UDP packets, dispatching to DNS parser if applicable."""
    ip_src, ip_dst = packet[IP].src, packet[IP].dst
    udp_sport, udp_dport = packet[UDP].sport, packet[UDP].dport

    # **THE FIX IS HERE**: Check for DNS inside the UDP block
    if DNS in packet and (udp_sport == 53 or udp_dport == 53):
        stats['protocols']['DNS'] += 1
        process_dns_packet(packet)
    else:
        print(f"[*] UDP: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

def process_dns_packet(packet):
    """Parses and displays DNS query and response details."""
    try:
        # DNS Query (qr=0)
        if packet[DNS].qr == 0 and packet[DNS].qd:
            query_name = packet[DNS].qd.qname.decode()
            print(f"[+] DNS Query: {packet[IP].src} requested {query_name}")
        # DNS Response (qr=1)
        elif packet[DNS].qr == 1 and packet[DNS].an:
            query_name = packet[DNS].qd.qname.decode()
            answers = [r.rdata for r in packet[DNS].an if hasattr(r, 'rdata')]
            ip_answers = [ans.decode() if isinstance(ans, bytes) else ans for ans in answers]
            print(f"[+] DNS Response: {query_name} -> {ip_answers}")
    except Exception as e:
        print(f"    [!] Error parsing DNS packet: {e}")

def process_ipv6_packet(packet):
    """Basic processing for IPv6 packets."""
    print(f"[*] IPv6: {packet[IPv6].src} -> {packet[IPv6].dst}")

def check_for_http_payload(packet):
    """Checks for and prints potential HTTP payloads."""
    try:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        http_methods = ["GET ", "POST ", "HTTP/1", "Host:"]
        if any(method in payload for method in http_methods):
            print(f"    [+] HTTP Payload: {payload.splitlines()[0]}")
    except:
        pass

def main():
    """Main function to parse arguments and start the sniffer."""
    parser = argparse.ArgumentParser(description="An enhanced network packet sniffer with threat detection.")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on.")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF filter (e.g., 'tcp port 80').")
    parser.add_argument("-o", "--output", type=str, help="Output file to save packets (.pcap).")
    
    args = parser.parse_args()

    # Register the summary function to run on exit
    atexit.register(print_summary)

    if args.output:
        global pcap_writer
        pcap_writer = PcapWriter(args.output, append=True, sync=True)

    print("--- Starting Enhanced Packet Sniffer ---")
    print("Press Ctrl+C to stop.")
    
    try:
        sniff(iface=args.interface, filter=args.filter, prn=process_packet, store=0)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        if 'pcap_writer' in globals():
            pcap_writer.close()
            print(f"[*] Packets saved to {args.output}")

if __name__ == "__main__":
    main()
