import psutil
from scapy.layers.inet import IP, UDP
from scapy.packet import Padding
from scapy.sendrecv import sniff
from scapy.utils import hexdump

from crewmate.dissector import register_layers, Dissector
from crewmate.packets import ChatRPC, Hazel, HazelTag, GameData, RPC, RPCAction, GameDataType


class Capturer:

    def __init__(self, pid):
        self.pid = pid
        print(f"Capturing PID: {pid}")

    def capture(self):
        process = psutil.Process(self.pid)
        connections = process.connections("udp")
        if not connections:
            print("Found no active connections")
            return
        print(f"Found {len(connections)} connections, picking first")
        connection = connections[0]
        dissector = Dissector()
        print(f"Using connection port {connection.laddr.port}")

        def callback(packet):
            return dissector.dissect_packet(packet)

        register_layers()
        sniff(prn=callback, filter=f"udp and port {connection.laddr.port}")
