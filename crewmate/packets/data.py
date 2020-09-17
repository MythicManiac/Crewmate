from scapy.fields import MSBExtendedField, ByteField, ShortField, StrLenField, PacketListField
from scapy.packet import Packet

from crewmate.utils import MSBExtendedFieldLenField


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
