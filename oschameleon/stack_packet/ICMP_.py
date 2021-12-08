#!/usr/bin/python

"""
Created on 24.09.2016

@author: manuel
"""

from IP_ import ReplyPacket
from helper import drop_packet
from helper import forward_packet
from scapy.all import IP, UDP, ICMP, send, Padding  # @UnresolvedImport


class ICMPPacket(ReplyPacket):
    """
    ICMP packet
    """

    def __init__(self, pkt, os_pattern, package_type):
        ReplyPacket.__init__(self, pkt, os_pattern)
        self.icmp = ICMP()
        self.pkt = pkt

        # type = 0 ^= echo reply
        if package_type == 0:
            self.icmp.type = 0
            self.icmp.id = pkt[ICMP].id
            self.icmp.seq = pkt[ICMP].seq
            self.data = pkt[ICMP].payload
        # type = 3 & code = 3 ^= port unreachable
        elif package_type == 3:
            self.icmp.type = 3
            self.icmp.code = 3
            self.icmp.unused = os_pattern.UN

    def set_ICMP_code(self, icmpc):
        self.icmp.code = icmpc

    # some OS reply with no data returned
    def clr_payload(self):
        self.pkt[UDP].payload = ""

    # echo reply
    def send_packet(self):
        send(self.ip / self.icmp / self.data, verbose=0)

    # port unreachable
    def send_PUR_packet(self):
        send(self.ip / self.icmp / self.pkt, verbose=0)


def send_ICMP_reply(pkt, ICMP_type, os_pattern, TCP_OPTIONS):
    """
    Send ICMP reply packet
    """
    # create reply packet and set flags
    icmp_rpl = ICMPPacket(pkt, os_pattern, ICMP_type)
    # set ICMP header fields
    icmp_rpl.set_DF(TCP_OPTIONS["DF"])

    # ICMP type = 0  =^ echo reply
    if ICMP_type == 0:
        icmp_rpl.set_IP_ID(os_pattern.IP_ID_II_CNT)
        # set ICMP code field
        if os_pattern.ICMP_CODE == "S":
            icmp_rpl.set_ICMP_code(pkt[ICMP].code)
        else:
            icmp_rpl.set_ICMP_code(os_pattern.ICMP_CODE)

        # send ICMP reply
        icmp_rpl.send_packet()

    # ICMP type = 3  =^ destination unreable
    elif ICMP_type == 3:
        icmp_rpl.set_IP_ID(1)
        # some OS reply with no data returned
        if os_pattern.CL_UDP_DATA:
            icmp_rpl.clr_payload()

        # template n1
        # n1 -> convert in hex
        #

        len_packet = int(str(len(icmp_rpl.pkt)), 16)
        if len_packet < os_pattern.ICMP_IPL:
            print("icmp input packet length: ", len_packet)
            pad_len = os_pattern.ICMP_IPL - len_packet - 16
            pad = Padding()
            pad.add_payload("\x00" * pad_len)
            icmp_rpl.pkt = icmp_rpl.pkt / pad
            print("icmp reply packet length: ", int(str(len(icmp_rpl.pkt)), 16))

        # send ICMP Port Unreachable
        icmp_rpl.send_PUR_packet()


def check_ICMP_probes(pkt, nfq_packet, os_pattern):
    """
    Identify the ICMP based probes
    and reply with a faked packet if needed
    """
    if pkt[ICMP].type is 8:
        # Probe 1 + 2
        if (
            pkt[ICMP].seq == 295
            and pkt[IP].flags == 0x02
            and len(pkt[ICMP].payload) == 120
        ) or (
            pkt[ICMP].seq == 296
            and pkt[IP].tos == 0x04
            and len(pkt[ICMP].payload) == 150
        ):
            drop_packet(nfq_packet)
            if os_pattern.PROBES_2_SEND["IE"]:
                # ICMP type = 0  =^ echo reply
                ICMP_type = 0
                send_ICMP_reply(
                    pkt, ICMP_type, os_pattern, os_pattern.TCP_OPTIONS["IE"]
                )
                # print "IE Probe"
        else:
            forward_packet(nfq_packet)
    else:
        forward_packet(nfq_packet)
