from scapy.fields import (
    ByteEnumField,
    ShortField,
    ConditionalField,
    PacketField,
    IntField,
    PacketListField,
    LEShortField,
)
from scapy.packet import Packet

from crewmate.packets.enums import (
    GameDataType,
    RoomMessageType,
    HazelType,
)
from crewmate.packets.rpc.rpc import RPC
from crewmate.utils import AmongUsEnvelope


class GameDataData(Packet):
    name = "GameDataData"
    fields_desc = [
    ]

    def extract_padding(self, p):
        return "", p


class GameData(AmongUsEnvelope, Packet):
    name = "GameData"
    fields_desc = [
        LEShortField("contentSize", None),
        ByteEnumField("type", None, GameDataType.as_dict()),
        ConditionalField(
            PacketField("RPC", None, RPC),
            lambda packet: packet.type == GameDataType.RPC,
        ),
        ConditionalField(
            PacketField("data", None, GameDataData),
            lambda packet: packet.type == GameDataType.DATA,
        ),
    ]


class RoomMessage(AmongUsEnvelope, Packet):
    name = "RoomMessage"
    fields_desc = [
        LEShortField("contentSize", None),
        ByteEnumField("type", None, RoomMessageType.as_dict()),
        IntField("roomCode", None),
        PacketListField("messages", [], cls=GameData),
    ]


class Hazel(Packet):
    name = "Hazel"
    fields_desc = [
        ByteEnumField("type", None, HazelType.as_dict()),
        ConditionalField(
            ShortField("packetId", None),
            lambda packet: packet.type in HazelType.get_reliable()
        ),
        PacketField("content", None, RoomMessage),
    ]

    def extract_padding(self, p):
        return "", p
