import psutil
from scapy.sendrecv import sniff

from crewmate.dissector import DiscordMuteDissector


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
        dissector = DiscordMuteDissector()
        print(f"Using connection port {connection.laddr.port}")

        def callback(packet):
            return dissector.dissect_packet(packet)

        sniff(prn=callback, filter=f"udp and port {connection.laddr.port}")
