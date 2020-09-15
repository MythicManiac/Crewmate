from scapy.packet import bind_layers
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from crewmate.packets import Hazel, GameData, RPC, ChatRPC, HazelTag, GameDataType, RPCAction


class Dissector:

    def __init__(self, filepath):
        self.filepath = filepath

    def process_pcap(self):
        print(f"Reading {self.filepath}")

        count = 0
        interesting_packet_count = 0

        bind_layers(UDP, Hazel)
        bind_layers(Hazel, GameData)
        bind_layers(GameData, RPC)
        bind_layers(RPC, ChatRPC)

        for (pkt_data, pkt_metadata,) in RawPcapReader(self.filepath):
            count += 1

            ether_pkt = Ether(pkt_data)
            if "type" not in ether_pkt.fields:
                continue

            if ether_pkt.type != 0x0800:
                continue

            ip_pkt = ether_pkt[IP]
            if ip_pkt.proto != 17:
                continue

            # # TODO: Remove
            # if ip_pkt.dst != "45.79.251.16":
            #     continue

            # if count != 5725:
            #     continue

            udp_pkt = ip_pkt[UDP]
            hazel_pkt = udp_pkt[Hazel]

            # print(hazel_pkt.hazelMarker)
            # print(hazel_pkt.show())
            # break

            if hazel_pkt.hazelTag != HazelTag.GAME_DATA:
                continue
            interesting_packet_count += 1

            game_data_pkt = hazel_pkt[GameData]
            if game_data_pkt.gameDataType != GameDataType.RPC:
                continue

            rpc_pkt = game_data_pkt[RPC]
            if rpc_pkt.rpcAction != RPCAction.SENDCHAT:
                continue

            rpc_chat = rpc_pkt[ChatRPC]
            print(rpc_chat.rpcChatMessage.decode("utf-8"))

        # print(f"{self.filepath} has {count} packets")
        # print(f"{self.filepath} has {interesting_packet_count} interesting packets")
