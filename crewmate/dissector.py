import requests

from scapy.packet import Padding, Raw
from scapy.utils import RawPcapReader, hexdump
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP

from crewmate.packets import RPC, RoomMessageType, RPCAction, RoomMessage, Hazel, HazelType
from settings import DISCORD_UNMUTE_URL, DISCORD_MUTE_URL


def unmute_discord():
    requests.get(DISCORD_UNMUTE_URL)


def mute_discord():
    requests.get(DISCORD_MUTE_URL)


class Dissector:

    def dissect_packet(self, packet):
        if UDP not in packet:
            return
        udp = packet[UDP]
        if Hazel not in packet:
            return
        if packet[Hazel].type != HazelType.RELIABLE:
            return
        udp.show()
        if Padding in udp:
            hexdump(udp[Padding])
        if Raw in udp:
            hexdump(udp[Raw])


class DiscordMuteDissector(Dissector):

    def dissect_packet(self, packet):
        if RoomMessage in packet:
            message = packet[RoomMessage]
            if message.hazelTag == RoomMessageType.START_GAME:
                mute_discord()
            if message.hazelTag == RoomMessageType.END_GAME:
                unmute_discord()
        if RPC in packet:
            rpc = packet[RPC]
            if rpc.rpcAction == RPCAction.STARTMEETING:
                unmute_discord()
            if rpc.rpcAction == RPCAction.CLOSE:
                mute_discord()


class PcapDissector(Dissector):

    def __init__(self, filepath):
        self.filepath = filepath
        super().__init__()

    def process_pcap(self):
        print(f"Reading {self.filepath}")

        count = 0
        for (packet, meta,) in RawPcapReader(self.filepath):
            count += 1
            res = self.dissect_packet(Ether(packet))
            if res:
                print(res)

        print(f"{self.filepath} has {count} packets")
