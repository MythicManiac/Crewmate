import requests

from scapy.packet import Padding, Raw
from scapy.utils import RawPcapReader, hexdump
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP

from crewmate.packets import RPC, RoomMessageType, RPCAction, RoomMessage, Hazel, HazelType
from crewmate.packets.rpc.update_game_data import UpdateGameDataRPC
from settings import DISCORD_UNMUTE_URL, DISCORD_MUTE_URL


def unmute_discord():
    requests.get(DISCORD_UNMUTE_URL)


def mute_discord():
    requests.get(DISCORD_MUTE_URL)


class GameTrackingDissector:

    def __init__(self):
        self.player_data = {}

    def dissect_packet(self, packet):
        if RoomMessage not in packet:
            return
        if UpdateGameDataRPC in packet:
            game_data = packet[UpdateGameDataRPC]
            for player in game_data.players:
                self.player_data[player.playerId] = player
                if player.statusBitField > 0:
                    return f"{player.playerName.decode('utf-8')} is the impostor"


class DebugPrintDissector:

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


class DiscordMuteDissector(DebugPrintDissector):

    def dissect_packet(self, packet):
        if RoomMessage in packet:
            message = packet[RoomMessage]
            if message.type == RoomMessageType.START_GAME:
                mute_discord()
            if message.type == RoomMessageType.END_GAME:
                unmute_discord()
        if RPC in packet:
            rpc = packet[RPC]
            if rpc.rpcAction == RPCAction.STARTMEETING:
                unmute_discord()
            if rpc.rpcAction == RPCAction.CLOSE:
                mute_discord()


class PcapDissector(DebugPrintDissector):

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
