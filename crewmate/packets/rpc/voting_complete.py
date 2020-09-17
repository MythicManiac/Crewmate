from scapy.packet import Packet


class VotingCompleteRPC(Packet):
    name = "VotingCompleteRPC"
    fields_desc = [
        # # Byte array of states
        # ByteField("playerId", None),  # 0xFF if nobody
        # ByteField("votingTie", None),
    ]

    def extract_padding(self, p):
        return "", p
