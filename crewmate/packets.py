from scapy.fields import (
    ByteEnumField,
    ShortField,
    ConditionalField,
    PacketField,
    IntField,
    StrLenField,
    MSBExtendedField,
    ByteField,
    PacketListField,
    LEShortField)
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


class MSBExtendedFieldLenField(MSBExtendedField):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, length_of=None, count_of=None, adjust=lambda pkt, x: x, fld=None):
        MSBExtendedField.__init__(self, name, default)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust
        if fld is not None:
            self.length_of = fld

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt, f)
        return x


class HazelType(PacketFieldEnum):
    UNRELIABLE = 0
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
        return {cls.UNRELIABLE, cls.DISCONNECT, cls.ACK, cls.FRAGMENT}


class ChatNoteTypes(PacketFieldEnum):
    DIDVOTE = 0


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
    UPDATEGAMEDATA = 30


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
        MSBExtendedFieldLenField("rpcChatLen", None, "rpcChatMessage"),
        StrLenField(
            "rpcChatMessage",
            None,
            length_from=lambda packet: packet.rpcChatLen
        ),
    ]

    def extract_padding(self, p):
        return "", p


class StartMeetingRPC(Packet):
    name = "StartMeetingRPC"
    fields_desc = [
        ByteField("playerId", None),
    ]

    def extract_padding(self, p):
        return "", p


class ReportDeadBodyRPC(Packet):
    name = "ReportDeadBodyRPC"
    fields_desc = [
        ByteField("playerId", None),
    ]

    def extract_padding(self, p):
        return "", p


class SendChatNoteRPC(Packet):
    name = "SendChatNoteRPC"
    fields_desc = [
        ByteField("playerId", None),
        ByteEnumField("chatNoteType", None, ChatNoteTypes.as_dict()),
    ]

    def extract_padding(self, p):
        return "", p


class VotingCompleteRPC(Packet):
    name = "VotingCompleteRPC"
    fields_desc = [
        # # Byte array of states
        # ByteField("playerId", None),  # 0xFF if nobody
        # ByteField("votingTie", None),
    ]

    def extract_padding(self, p):
        return "", p


class TaskData(Packet):
    name = "TaskData"
    fields_desc = [
        MSBExtendedField("taskId", None),
        ByteField("complete", None),
    ]

    def extract_padding(self, p):
        return "", p


class PlayerData(Packet):
    name = "PlayerData"
    fields_desc = [
        ShortField("updateGameDataLen", None),
        ByteField("playerId", None),
        MSBExtendedFieldLenField("playerNameLen", None, "playerName"),
        StrLenField(
            "playerName", None,
            length_from=lambda packet: packet.playerNameLen
        ),
        ByteField("colorId", None),
        MSBExtendedField("hatId", None),
        MSBExtendedField("petId", None),
        MSBExtendedField("skinId", None),
        ByteField("statusBitField", None),  # TODO: Convert to BitField
        ByteField("taskCount", None),
        PacketListField(
            "tasks", [], cls=TaskData,
            count_from=lambda packet: packet.taskCount,
        ),
    ]

    def extract_padding(self, p):
        return "", p


class UpdateGameDataRPC(Packet):
    name = "UpdateGameDataRPC"
    fields_desc = [
        PacketListField("players", [], cls=PlayerData)
    ]

    def extract_padding(self, p):
        return "", p


class SetStartCounterRPC(Packet):
    name = "SetStartCounterRPC"
    fields_desc = [
    ]

    def extract_padding(self, p):
        return "", p


class SetHatRPC(Packet):
    name = "SetHatRPC"
    fields_desc = [
        MSBExtendedField("hatId", None),
    ]

    def extract_padding(self, p):
        return "", p


class RPC(Packet):
    name = "RPC"
    fields_desc = [
        MSBExtendedField("rpcTargetId", None),
        ByteEnumField("rpcAction", None, RPCAction.as_dict()),
        ConditionalField(
            PacketField("ChatRPC", None, ChatRPC),
            lambda packet: packet.rpcAction == RPCAction.SENDCHAT,
        ),
        ConditionalField(
            PacketField("SetStartCounterRPC", None, SetStartCounterRPC),
            lambda packet: packet.rpcAction == RPCAction.SETSTARTCOUNTER,
        ),
        ConditionalField(
            PacketField("SetHatRPC", None, SetHatRPC),
            lambda packet: packet.rpcAction == RPCAction.SETHAT,
        ),
        ConditionalField(
            PacketField("StartMeetingRPC", None, StartMeetingRPC),
            lambda packet: packet.rpcAction == RPCAction.STARTMEETING,
        ),
        ConditionalField(
            PacketField("VotingCompleteRPC", None, VotingCompleteRPC),
            lambda packet: packet.rpcAction == RPCAction.VOTINGCOMPLETE,
        ),
        ConditionalField(
            PacketField("SendChatNoteRPC", None, SendChatNoteRPC),
            lambda packet: packet.rpcAction == RPCAction.SENDCHATNOTE,
        ),
        ConditionalField(
            PacketField("ReportDeadBodyRPC", None, ReportDeadBodyRPC),
            lambda packet: packet.rpcAction == RPCAction.REPORTDEADBODY,
        ),
        ConditionalField(
            PacketField("UpdateGameDataRPC", None, UpdateGameDataRPC),
            lambda packet: packet.rpcAction == RPCAction.UPDATEGAMEDATA,
        )
    ]

    def extract_padding(self, p):
        return "", p


class GameDataData(Packet):
    name = "GameDataData"
    fields_desc = [
    ]

    def extract_padding(self, p):
        return "", p


class GameData(Packet):
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

    def extract_padding(self, p):
        return "", p


class GameDataEnvelope(Packet):
    name = "GameDataEnvelope"
    fields_desc = [
        IntField("roomCode", None),
        PacketListField("messages", [], cls=GameData, count_from=lambda x: 1),
    ]

    def extract_padding(self, p):
        return "", p


class Hazel(Packet):
    name = "Hazel"
    fields_desc = [
        ByteEnumField("type", None, HazelType.as_dict()),
        ConditionalField(
            ShortField("hazelPacketId", None),
            lambda packet: packet.type in HazelType.get_reliable()
        ),
        LEShortField("hazelContentSize", None),
        ByteEnumField("hazelTag", None, HazelTag.as_dict()),
        ConditionalField(
            PacketField("GameDataEnvelope", None, GameDataEnvelope),
            lambda packet: packet.hazelTag == HazelTag.GAME_DATA
        ),
    ]

    def extract_padding(self, p):
        return "", p
