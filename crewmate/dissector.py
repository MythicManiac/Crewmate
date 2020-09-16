import requests

from scapy.packet import bind_layers, Padding
from scapy.utils import RawPcapReader, hexdump
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP

from crewmate.packets import Hazel, GameDataEnvelope, RPC, ChatRPC, HazelTag, RPCAction

LAYERS_BOUND = False


def unmute_discord():
    requests.get("unmute url")


def mute_discord():
    requests.get("mute url")


def register_layers():
    global LAYERS_BOUND
    if not LAYERS_BOUND:
        bind_layers(UDP, Hazel)
        bind_layers(Hazel, GameDataEnvelope)
        bind_layers(GameDataEnvelope, RPC)
        bind_layers(RPC, ChatRPC)
        LAYERS_BOUND = True


class Dissector:

    def __init__(self):
        register_layers()

    def dissect_packet(self, packet):
        if UDP not in packet:
            return
        udp = packet[UDP]
        if RPC not in packet:
            return
        udp.show()
        if Padding in udp:
            hexdump(udp[Padding])


class DiscordMuteDissector(Dissector):

    def dissect_packet(self, packet):
        # result = super().dissect_packet(packet)
        if Hazel in packet:
            hazel = packet[Hazel]
            if hazel.hazelTag == HazelTag.START_GAME:
                mute_discord()
            if hazel.hazelTag == HazelTag.END_GAME:
                unmute_discord()
        if RPC in packet:
            rpc = packet[RPC]
            if rpc.rpcAction == RPCAction.STARTMEETING:
                unmute_discord()
            if rpc.rpcAction == RPCAction.CLOSE:
                mute_discord()
        # return result


class PcapDissector(Dissector):

    def __init__(self, filepath):
        self.filepath = filepath
        super().__init__()

    def process_pcap(self):
        print(f"Reading {self.filepath}")
        register_layers()

        count = 0
        for (packet, meta,) in RawPcapReader(self.filepath):
            count += 1
            res = self.dissect_packet(Ether(packet))
            if res:
                print(res)

        print(f"{self.filepath} has {count} packets")
