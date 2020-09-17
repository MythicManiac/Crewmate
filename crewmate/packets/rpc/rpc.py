from scapy.fields import MSBExtendedField, ByteEnumField, ConditionalField, PacketField
from scapy.packet import Packet

from crewmate.packets.enums import RPCAction
from crewmate.packets.rpc.report_dead_body import ReportDeadBodyRPC
from crewmate.packets.rpc.send_chat import SendChatRPC
from crewmate.packets.rpc.send_chat_note import SendChatNoteRPC
from crewmate.packets.rpc.set_hat import SetHatRPC
from crewmate.packets.rpc.set_start_counter import SetStartCounterRPC
from crewmate.packets.rpc.start_meeting import StartMeetingRPC
from crewmate.packets.rpc.update_game_data import UpdateGameDataRPC
from crewmate.packets.rpc.voting_complete import VotingCompleteRPC


class RPC(Packet):
    name = "RPC"
    fields_desc = [
        MSBExtendedField("rpcTargetId", None),
        ByteEnumField("rpcAction", None, RPCAction.as_dict()),
        ConditionalField(
            PacketField("sendChat", None, SendChatRPC),
            lambda packet: packet.rpcAction == RPCAction.SENDCHAT,
        ),
        ConditionalField(
            PacketField("setStartCounter", None, SetStartCounterRPC),
            lambda packet: packet.rpcAction == RPCAction.SETSTARTCOUNTER,
        ),
        ConditionalField(
            PacketField("setHat", None, SetHatRPC),
            lambda packet: packet.rpcAction == RPCAction.SETHAT,
        ),
        ConditionalField(
            PacketField("startMeeting", None, StartMeetingRPC),
            lambda packet: packet.rpcAction == RPCAction.STARTMEETING,
        ),
        ConditionalField(
            PacketField("votingComplete", None, VotingCompleteRPC),
            lambda packet: packet.rpcAction == RPCAction.VOTINGCOMPLETE,
        ),
        ConditionalField(
            PacketField("sendChatNoteR", None, SendChatNoteRPC),
            lambda packet: packet.rpcAction == RPCAction.SENDCHATNOTE,
        ),
        ConditionalField(
            PacketField("reportDeadBody", None, ReportDeadBodyRPC),
            lambda packet: packet.rpcAction == RPCAction.REPORTDEADBODY,
        ),
        ConditionalField(
            PacketField("updateGameData", None, UpdateGameDataRPC),
            lambda packet: packet.rpcAction == RPCAction.UPDATEGAMEDATA,
        )
    ]

    def extract_padding(self, p):
        return "", p
