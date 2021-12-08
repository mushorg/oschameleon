#!/usr/bin/python
# Copyright (c) 2015 Anton Hinterleitner, Lukas Rist
"""
Description: Fools the probes of nmap scanner

Prerequisites: Linux
               Python 2.6+
               python-nfqueue
               scapy

Note:          This script flushes iptables before and after usage.

OS fingerprint from Nmap database:

SEQ(SP=0-5%GCD=FA7F|1F4FE|2EF7D|3E9FC|4E47B%ISR=94-9E%TI=I%CI=I%II=I%SS=S%TS=U)
OPS(R=N)
WIN(R=N)
ECN(R=N)
T1(R=Y%DF=N%T=19-23%TG=20%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=N%T=19-23%TG=20%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=N%T=19-23%TG=20%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%T=19-23%TG=20%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
U1(DF=N%T=19-23%TG=20%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(DFI=N%T=19-23%TG=20%CD=S)


Running: Siemens embedded
OS CPE: cpe:/h:siemens:simatic_300
OS details: Siemens Simatic 300 programmable logic controller
Network Distance: 1 hop
-----

"""
# import needed Scapy modules
# Log error messages only


import gevent
import logging
import nfqueue
import os
import socket

from parse_fp import get_os_pattern
from scapy.all import IP, TCP, UDP, ICMP  # @UnresolvedImport
from scapy.config import conf  # @UnresolvedImport
from scapy.supersocket import L3RawSocket  # @UnresolvedImport
import session
from stack_packet.ICMP_ import check_ICMP_probes
from stack_packet.TCP_ import check_TCP_probes
from stack_packet.UDP_ import check_UDP_probe
from stack_packet.helper import flush_tables
from stack_packet.helper import forward_packet
from stack_packet.helper import rules


# from session.log import Log
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Set Scapy settings
conf.verbose = 0
# using a PF INET/SOCK RAW
conf.L3socket = L3RawSocket

# ----------------------------------------------------------
# CONSTANTS - Nmap probes
# ----------------------------------------------------------


class ProcessPKT(object):
    """
    Do a separation according to the TCP/IP trasport layer
    check if the packet is a nmap probe and send OS specific replies
    """
    def __init__(self, os_pattern, session, debug):
        self.os_pattern = os_pattern
        self.session = session
        self.debug = debug

    def callback(self, nfq_packet):
        # Get packetdata from nfqueue packet and build a Scapy packet
        pkt = IP(nfq_packet.get_data())

        # check TCP packets
        if pkt.haslayer(TCP):
            check_TCP_probes(pkt, nfq_packet, self.os_pattern, self.session, self.debug)

        # check ICMP packets
        elif pkt.haslayer(ICMP):
            check_ICMP_probes(pkt, nfq_packet, self.os_pattern)

        # check UDP packets
        elif pkt.haslayer(UDP):
            check_UDP_probe(pkt, nfq_packet, self.os_pattern)

        # don't analyse it, continue to destination
        else:
            forward_packet(nfq_packet)
        return 0


class OSFuscation(object):

    @classmethod
    def worker(cls, queue):
        while True:
            queue.process_pending(5)

    @classmethod
    def run(cls, debug=False, template_path='', server_ip=None):

        # check if root
        if not os.geteuid() == 0:
            exit("\nPlease run as root\n")

        os_pattern = get_os_pattern(template_path, debug)

        if debug:
            print('*' * 30)
            print(os_pattern)
            print('*' * 30)

        # Flush the IP tables first
        flush_tables()

        # set iptables rules
        rules(server_ip)
        session_ = session.get_Session()

        # creation of a new queue object
        q = nfqueue.queue()
        q.set_callback(ProcessPKT(os_pattern, session_, debug).callback)
        q.fast_open(0, socket.AF_INET)
        q.set_queue_maxlen(-1)

        # process queue for packet manipulation
        try:
            workers = list()
            for i in range(2):
                workers.append(gevent.spawn(cls.worker, q))
            gevent.joinall(workers)
        except KeyboardInterrupt:
            # on exit clean up
            q.unbind(socket.AF_INET)
            q.close()
            flush_tables()
            print('Exiting...')


if __name__ == '__main__':
    OSFuscation.run()
