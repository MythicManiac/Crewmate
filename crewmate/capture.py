import psutil
from scapy.sendrecv import sniff

from crewmate.dissector import DiscordMuteDissector


class Capturer:

    def __init__(self, pid):
        self.pid = pid

    def get_pid(self):
        if self.pid:
            return self.pid
        for p in psutil.process_iter(attrs=["name", "pid"]):
            if p.name() == "Among Us.exe":
                return p.pid
        raise RuntimeError("Among Us.exe is not running")

    def capture(self):
        pid = self.get_pid()
        print(f"Capturing PID: {pid}")
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
