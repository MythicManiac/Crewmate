from scapy.fields import MSBExtendedField
from scapy.packet import Packet


class ExitVentRPC(Packet):
    name = "ExitVentRPC"
    fields_desc = [
        # TODO: Confirm
        MSBExtendedField("ventId", None),
    ]

    def extract_padding(self, p):
        return "", p
