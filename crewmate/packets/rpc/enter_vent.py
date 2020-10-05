from scapy.fields import MSBExtendedField
from scapy.packet import Packet


class EnterVentRPC(Packet):
    name = "EnterVentRPC"
    fields_desc = [
        # TODO: Confirm
        MSBExtendedField("ventId", None),
    ]

    def extract_padding(self, p):
        return "", p
