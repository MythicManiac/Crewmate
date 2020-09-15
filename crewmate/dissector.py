from scapy.packet import bind_layers
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from crewmate.packets import Hazel, GameData, RPC, ChatRPC, HazelTag, GameDataType, RPCAction

LAYERS_BOUND = False


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
            return

        # print("### Hazel ###")
        # print(f"Marker: {hazel_pkt.hazelMarker}")
        # print(f"Size: {hazel_pkt.hazelPacketSize}")
        # print(f"Tag: {hazel_pkt.hazelTag}")

        game_data_pkt = hazel_pkt[GameData]
        if game_data_pkt.gameDataType != GameDataType.RPC:
            return

        # print("### GameData ###")
        # print(f"gameDataCode: {game_data_pkt.gameDataCode}")
        # print(f"gameDataLength: {game_data_pkt.gameDataLength}")
        # print(f"gameDataType: {game_data_pkt.gameDataType}")

        rpc_pkt = game_data_pkt[RPC]

        # print("### RPC ###")
        # print(f"rpcTargetId: {rpc_pkt.rpcTargetId}")
        # print(f"rpcAction: {rpc_pkt.rpcAction}")

        action = rpc_pkt.rpcAction
        action_name = RPCAction.as_dict().get(action, "UNKNOWN")
        if action != RPCAction.SENDCHAT:
            return f"{action_name}"

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
            # if count != 2430:
            #     continue
            res = self.dissect_packet(Ether(packet))
            if res:
                print(res)
            # break

        print(f"{self.filepath} has {count} packets")
