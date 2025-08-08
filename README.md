# 🐍 Enhanced Python Packet Sniffer

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)

A powerful, command-line packet sniffer built with Python and Scapy. This tool allows you to capture and inspect network traffic in real-time, log data, and perform basic threat detection.

---

## ## Features

* **Live Packet Capture:** Sniff network packets on any specified network interface.
* **Protocol Dissection:** Analyzes and displays data from `IPv4`, `IPv6`, `TCP`, `UDP`, and `ARP` layers.
* **PCAP Logging:** Save captured traffic directly to a `.pcap` file for later analysis in tools like Wireshark.
* **🛡️ ARP Spoofing Detection:** Monitors ARP replies and alerts you if an IP address suddenly claims a new MAC address.
* **👁️ Port Scan Detection:** Detects and flags rapid `TCP SYN` requests from a single source to a single destination.
* **Powerful Filtering:** Uses BPF (Berkeley Packet Filter) syntax to capture only the traffic you care about.
* **Command-Line Interface:** Easy-to-use flags for specifying interfaces, filters, and output files.

---

## ## 🛠️ Prerequisites

Before you begin, ensure you have the following installed:

1.  **Python 3.7+**
2.  **Scapy:** The core packet manipulation library.
    ```bash
    pip install scapy
    ```
3.  **Packet Capture Driver:** Scapy needs a low-level driver to interact with the network interface.
    * **Windows:** You must install **Npcap**.
        * Download from the [Npcap website](https://npcap.com/#download).
        * **Important:** During installation, select the option **"Install Npcap in WinPcap API-compatible Mode"**.
    * **Linux / macOS:** You'll need `libpcap`. It is typically pre-installed on most modern systems.

---

## ## 🚀 Usage

This script must be run with **root or administrator privileges** to allow for raw socket access.

### ### Command-Line Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-i`, `--interface` | `eth0` | Network interface to sniff on. |
| `-f`, `--filter` | `"tcp port 80"` | BPF filter to apply to the capture. |
| `-o`, `--output` | `capture.pcap` | Output file to save captured packets. |
| `-h`, `--help` | | Show the help message. |

### ### Examples

* **Sniff all traffic and print to console:**
    ```bash
    # On Linux/macOS
    sudo python3 sniffer.py

    # On Windows (in an Administrator PowerShell/CMD)
    python sniffer.py
    ```

* **Sniff on a specific interface and save to a file:**
    ```bash
    sudo python3 sniffer.py -i eth0 -o traffic_log.pcap
    ```

* **Capture only DNS traffic and save it:**
    ```bash
    sudo python3 sniffer.py -f "udp port 53" -o dns_queries.pcap
    ```

---

## ## ⚠️ Disclaimer

This tool is intended for educational purposes and for use on networks where you have explicit permission to capture traffic. Unauthorized packet sniffing is illegal and unethical. The author is not responsible for any misuse of this tool.