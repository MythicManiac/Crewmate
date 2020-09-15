from scapy.all import *


def sniffer_callback(packet):
    return packet.sprintf("Got dem packets")


sniff(prn=sniffer_callback, filter="udp and host 192.168.1.110", store=0)

