#!/usr/bin/python
"""
Created on 24.09.2016

@author: manuel
"""

from ICMP_ import send_ICMP_reply
from helper import drop_packet
from helper import forward_packet
from scapy.all import IP, UDP  # @UnresolvedImport


def check_UDP_probe(pkt, nfq_packet, os_pattern):
    """
    Identify the UDP based probe
    and reply with a faked reply if needed
    """
    if (
        pkt[IP].id == 0x1042
        and pkt[UDP].payload.load[0] == "C"
        and pkt[UDP].payload.load[1] == "C"
        and pkt[UDP].payload.load[2] == "C"
    ):
        drop_packet(nfq_packet)
        if os_pattern.PROBES_2_SEND["U1"]:
            # create reply packet (ICMP port unreachable)
            # ICMP type = 3  =^ destination unreable
            ICMP_type = 3
            send_ICMP_reply(pkt, ICMP_type, os_pattern, os_pattern.TCP_OPTIONS["U1"])
            # print "U1 Probe"

    else:
        forward_packet(nfq_packet)
