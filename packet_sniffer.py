import optparse
import scapy.all as scapy
from scapy.layers import http


def get_arguments():
    pass

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

sniff("eth0")