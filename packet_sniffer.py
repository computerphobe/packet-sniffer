#!/usr/bin/env python3

import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    """
    This function is called for each captured packet.
    It dissects and prints information about the packet.
    """
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Identify the protocol
        if TCP in packet:
            # If it's a TCP packet, print source and destination ports
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"[*] TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            
            # Attempt to decode and display the payload for common text protocols
            check_for_payload(packet)

        elif UDP in packet:
            # If it's a UDP packet, print source and destination ports
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"[*] UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
            
            # Attempt to decode and display the payload
            check_for_payload(packet)
            
        else:
            # If it's another IP protocol (like ICMP)
            print(f"[*] Other IP Packet: {ip_src} -> {ip_dst} | Protocol: {packet[IP].proto}")


def check_for_payload(packet):
    """
    Checks for and prints the raw payload of a packet if it exists.
    Specifically looks for unencrypted HTTP GET/POST requests.
    """
    if Raw in packet:
        # The Raw layer contains the payload data
        payload = packet[Raw].load
        
        # Try to decode the payload as UTF-8 text
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
            
            # A simple check for common HTTP methods in the payload
            http_methods = ["GET ", "POST ", "HTTP/1", "Host:"]
            if any(method in decoded_payload for method in http_methods):
                print("    [+] Found potential HTTP Traffic:")
                # Print the first line of the payload for brevity
                print(f"    {decoded_payload.splitlines()[0]}")

        except Exception as e:
            # If decoding fails, just note that there is a payload
            print("    [+] Payload found, but could not decode as text.")


def main():
    """
    Main function to parse arguments and start the sniffer.
    """
    # Setup command-line argument parser
    parser = argparse.ArgumentParser(description="A simple network packet sniffer.")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on (e.g., eth0, wlan0).")
    parser.add_argument("-f", "--filter", type=str, help="BPF filter for sniffing (e.g., 'tcp port 80').")
    
    args = parser.parse_args()

    print("--- Starting Packet Sniffer ---")
    if args.interface:
        print(f"[*] Sniffing on interface: {args.interface}")
    if args.filter:
        print(f"[*] Applying BPF filter: {args.filter}")
    print("-------------------------------")

    # Start the sniffer
    # 'prn' specifies the callback function for each packet
    # 'store=0' tells Scapy not to keep packets in memory, saving resources
    # 'iface' and 'filter' are set from the command line arguments
    try:
        sniff(iface=args.interface, filter=args.filter, prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("[!] Make sure you are running this script with root/administrator privileges.")
        print("[!] On Windows, ensure Npcap is installed correctly.")


if __name__ == "__main__":
    main()