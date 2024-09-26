
# Packet Sniffer

This is a basic packet sniffer built using Python and the Scapy library. It listens to traffic on a specified network interface, filters HTTP requests, and looks for potential sensitive information such as usernames and passwords in the raw packet data.

## Prerequisites

- Python 3.x
- Scapy library

You can install the necessary dependencies by running:

```
pip install scapy
```

## How It Works

- The script sniffs network traffic on a specified interface.
- It looks for HTTP requests and prints the URLs that are being accessed.
- The program also scans for sensitive information like usernames and passwords in the packet payloads.

## Usage

To run the packet sniffer, simply execute the script and specify the network interface you want to monitor (e.g., `eth0`):

```
sudo python3 packet_sniffer.py
```

Replace `"eth0"` with the network interface you want to sniff.

## Code Breakdown

- `get_arguments()`: (Placeholder for future argument parsing)
  
- `sniff(interface)`: Starts sniffing traffic on the specified network interface.
  
- `process_packet(packet)`: This function processes each packet. If the packet contains an HTTP request, it extracts and prints the requested URL. It also scans the packet for sensitive information like usernames and passwords.

## Example Output

When the sniffer detects an HTTP request, it will output something like:

```
HTTP Request >> b'example.com/login'
[+] Possible Authentication > b'username=admin&password=123456'
```

## Disclaimer

This tool is intended for educational purposes only. Unauthorized packet sniffing or data interception is illegal and unethical. Always ensure you have permission before using this tool on any network.
