from scapy.fields import (
    ByteEnumField,
    ShortField,
    ConditionalField,
    PacketField,
    IntField,
    ByteField,
    FieldLenField,
    StrLenField,
)
from scapy.packet import Packet


class PacketFieldEnum:
    @classmethod
    def as_dict(cls):
        return {
            value: key
            for key, value in vars(cls).items()
            if not key.startswith("_")
            and any(
                (
                    isinstance(value, str),
                    isinstance(value, int),
                    isinstance(value, float),
                    isinstance(value, list),
                    isinstance(value, dict),
                )
            )
        }


class HazelMarker(PacketFieldEnum):
    NONE = 0
    RELIABLE = 1
    HELLO = 8
    DISCONNECT = 9
    ACK = 10
    FRAGMENT = 11
    PING = 12

    @classmethod
    def get_reliable(cls):
        return {cls.RELIABLE, cls.HELLO, cls.PING}

    @classmethod
    def get_unreliable(cls):
        return {cls.NONE, cls.DISCONNECT, cls.ACK, cls.FRAGMENT}


class RPCAction(PacketFieldEnum):
    PLAYANIMATION = 0
    COMPLETETASK = 1
    SYNCSETTINGS = 2
    SETINFECTED = 3
    EXILED = 4
    CHECKNAME = 5
    SETNAME = 6
    CHECKCOLOR = 7
    SETCOLOR = 8
    SETHAT = 9
    SETSKIN = 10
    REPORTDEADBODY = 11
    MURDERPLAYER = 12
    SENDCHAT = 13
    STARTMEETING = 14
    SETSCANNER = 15
    SENDCHATNOTE = 16
    SETPET = 17
    SETSTARTCOUNTER = 18
    ENTERVENT = 19
    EXITVENT = 20
    SNAPTO = 21
    CLOSE = 22
    VOTINGCOMPLETE = 23
    CASTVOTE = 24
    CLEARVOTE = 25
    ADDVOTE = 26
    CLOSEDOORSOFTYPE = 27
    REPAIRSYSTEM = 28
    SETTASKS = 29
    UPDATEGAMEDAT = 30


class HazelTag(PacketFieldEnum):
    HOST_GAME = 0
    JOIN_GAME = 1
    START_GAME = 2
    REMOVE_GAME = 3
    REMOVE_PLAYER = 4
    GAME_DATA = 5
    GAME_DATA_TO = 6
    JOINED_GAME = 7
    END_GAME = 8
    GET_GAME_LIST = 9
    ALTER_GAME = 10
    KICK_PLAYER = 11
    WAIT_FOR_HOST = 12
    REDIRECT = 13
    RESELECT_SERVER = 14


class GameDataType(PacketFieldEnum):
    DATA = 1
    RPC = 2
    SPAWN = 4
    DESPAWN = 5
    SCENE_CHANGE = 6
    READY = 7
    CHANGE_SETTINGS = 8


class ChatRPC(Packet):
    name = "ChatRPC"
    fields_desc = [
        # TODO: Use compressed int for len
        FieldLenField("rpcChatLen", None, "rpcChatMessage", fmt="B"),
        StrLenField(
            "rpcChatMessage",
            None,
            length_from=lambda packet: packet.rpcChatLen
        ),
    ]


class RPC(Packet):
    name = "RPC"
    fields_desc = [
        ByteField("rpcTargetId", None),
        ByteEnumField("rpcAction", None, RPCAction.as_dict()),
        ConditionalField(
            PacketField("ChatRPC", None, ChatRPC),
            lambda packet: packet.rpcAction == RPCAction.SENDCHAT,
        ),
    ]


class GameData(Packet):
    name = "GameData"
    fields_desc = [
        IntField("gameDataCode", None),
        ShortField("gameDataLength", None),
        ByteEnumField("gameDataType", None, GameDataType.as_dict()),
        ConditionalField(
            PacketField("RPC", None, RPC),
            lambda packet: packet.gameDataType == GameDataType.RPC,
        ),
    ]


class Hazel(Packet):
    name = "Hazel"
    fields_desc = [
        ByteEnumField("hazelMarker", None, HazelMarker.as_dict()),
        ConditionalField(
            ShortField("hazelPacketId", None),
            lambda packet: packet.hazelMarker in HazelMarker.get_reliable()
        ),
        ShortField("hazelPacketSize", None),
        ByteEnumField("hazelTag", None, HazelTag.as_dict()),
        ConditionalField(
            PacketField("GameData", None, GameData),
            lambda packet: packet.hazelTag == HazelTag.GAME_DATA
        ),
    ]


# class MainPacket(Packet):
#     fields_desc = [
#         IntEnumField("record_type", 1, {
#             3:"DATA_LONG",
#             8:"DATA_SZ"}),
#         FieldLenField("record_nb", 0, fmt="I", count_of="records"),
#         ConditionalField(
#             PacketListField(
#                 "records", None, RecordLONG, count_from=lambda pkt:pkt.record_nb),
#             lambda pkt: pkt.record_type == 3),
#         ConditionalField(
#             PacketListField(
#                 "records", None, RecordSZ, count_from=lambda pkt:pkt.record_nb),
#             lambda pkt: pkt.record_type == 8),
#     ]
