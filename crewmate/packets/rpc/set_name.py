from scapy.fields import StrLenField
from scapy.packet import Packet

from crewmate.utils import MSBExtendedFieldLenField


class SetNameRPC(Packet):
    name = "SetNameRPC"
    fields_desc = [
        MSBExtendedFieldLenField("length", None, "name"),
        StrLenField(
            "name",
            None,
            length_from=lambda packet: packet.length
        ),
    ]

    def extract_padding(self, p):
        return "", p
