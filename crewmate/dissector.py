import requests

from scapy.packet import bind_layers
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from crewmate.packets import Hazel, GameData, RPC, ChatRPC, HazelTag, GameDataType, RPCAction

LAYERS_BOUND = False


def unmute_discord():
    requests.get("unmute url")


def mute_discord():
    requests.get("mute url")


def register_layers():
    global LAYERS_BOUND
    if not LAYERS_BOUND:
        bind_layers(UDP, Hazel)
        bind_layers(Hazel, GameData)
        bind_layers(GameData, RPC)
        bind_layers(RPC, ChatRPC)
        LAYERS_BOUND = True


class Dissector:

    def dissect_packet(self, packet):
        register_layers()
        if "type" not in packet.fields:
            return

        if packet.type != 0x0800:
            return

        ip_pkt = packet[IP]
        if ip_pkt.proto != 17:
            return

        udp_pkt = ip_pkt[UDP]
        hazel_pkt = udp_pkt[Hazel]

        if hazel_pkt.hazelTag != HazelTag.GAME_DATA:
            if hazel_pkt.hazelTag == HazelTag.START_GAME:
                mute_discord()
            if hazel_pkt.hazelTag == HazelTag.END_GAME:
                unmute_discord()
            return

        game_data_pkt = hazel_pkt[GameData]
        if game_data_pkt.gameDataType != GameDataType.RPC:
            return

        rpc_pkt = game_data_pkt[RPC]

        action = rpc_pkt.rpcAction
        action_name = RPCAction.as_dict().get(action, "UNKNOWN")
        if action != RPCAction.SENDCHAT:

            if action == RPCAction.STARTMEETING:
                unmute_discord()
            if action == RPCAction.CLOSE:
                mute_discord()

            return rpc_pkt.show()

        rpc_chat = rpc_pkt[ChatRPC]
        message = rpc_chat.rpcChatMessage.decode("utf-8")
        return f"{action_name}: {message}"


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
