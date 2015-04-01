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

import random
import math
import struct
import os
import socket

import nfqueue
import gevent

# import needed Scapy modules
import logging
# Log error messages only
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.all import IP, TCP, UDP, ICMP, send

from parse_fp import get_os_pattern

# Set Scapy settings
conf.verbose = 0
# using a PF INET/SOCK RAW
conf.L3socket = L3RawSocket

# ----------------------------------------------------------
# CONSTANTS - Nmap probes
# ----------------------------------------------------------

# The TCP Option fields in the Nmap probes
NMAP_PROBE_TCP_OPTION = {
    'P1': [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (4294967295, 0)), ('SAckOK', '')],
    'P2': [('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('EOL', None)],
    'P3': [('Timestamp', (4294967295, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)],
    'P4': [('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)],
    'P5': [('MSS', 536), ('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)],
    'P6': [('MSS', 265), ('SAckOK', ''), ('Timestamp', (4294967295, 0))],
    'ECN': [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('NOP', None)],
    'T2-T6': [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', '')],
    'T7': [('WScale', 15), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', '')]}

# The TCP Window Size and TCP Flags wich have to match
NMAP_PROBE_TCP_ATTR = {
    'P1': {'WSZ': 1, 'FLGS': 0x02},
    'P2': {'WSZ': 63, 'FLGS': 0x02},
    'P3': {'WSZ': 4, 'FLGS': 0x02},
    'P4': {'WSZ': 4, 'FLGS': 0x02},
    'P5': {'WSZ': 16, 'FLGS': 0x02},
    'P6': {'WSZ': 512, 'FLGS': 0x02},
    'ECN': {'WSZ': 3, 'FLGS': 0xc2},
    'T2': {'WSZ': 128, 'FLGS': 0},
    'T3': {'WSZ': 256, 'FLGS': 0x02b},
    'T4': {'WSZ': 1024, 'FLGS': 0x010},
    'T5': {'WSZ': 31337, 'FLGS': 0x002},
    'T6': {'WSZ': 32768, 'FLGS': 0x010},
    'T7': {'WSZ': 65535, 'FLGS': 0x029}
}

# Flags in IP Header
# 0x02 ^= DF-Bit
NMAP_PROBE_IP_ATTR = {
    'T2': {'FLGS': 0x02},
    'T4': {'FLGS': 0x02},
    'T6': {'FLGS': 0x02}
}

# TCP Urgent Pointer in ECN probe
ECN_URGT_PTR = 0xF7F5


# \ End of CONSTANTS
# ----------------------------------------------------------

# Change MAC Address
# ------------------
# 00:1C:06:FF:DE:A4       -   Siemens Numerical Control Ltd
# 00:1F:F8:FF:DE:A4	-   Siemens AG, Sector Industry
# 00:08:74			-   DELL
# 00:0C:29:6A:9C:C1  -   Vmware
#
# nmap mapping to vendors /usr/share/nmap/nmap-mac-prefixes

# os.system('ifconfig eth0 down')
# os.system('ifconfig eth0 hw ether 00:1F:F8:FF:DE:A4')
# os.system('ifconfig eth0 up')


class OSPatternTemplate(object):
    """
    Defining the OS characteristics
    Take the values from the Nmap fingerprint
    """
    def __init__(self):
        self.TTL = 0x20

        # SEQ probes
        # GCD Greatest common divisor
        self.GCD = 0xFA7F

        # ISR Initial SEQNr counter rate
        self.ISR_MIN = 0x94
        self.ISR_MAX = 0x9E

        # SP (standard deviation of Initial SEQNr)
        self.SP_MIN = 0
        self.SP_MAX = 5

        # start value of SEQNR
        self.TCP_SEQ_NR_tmp = random.randint(1, 10)

        # TI - CI - II
        # difference of IP header ID fields by different response groups
        #  I (incremental)
        #  RI (random positive increments)
        #  BI (broken increment)
        self.IP_ID_TI_CNT = 'I'				# SEQ - TI field
        self.IP_ID_CI_CNT = 'I'			    # T5-7 - CI field
        self.IP_ID_II_CNT = 'I'				# IE - II field
        self.IP_ID_tmp = 1

        # Timestamp in reply packets
        self.TCP_Timestamp_tmp = 1
        # Timestamp counter 1... if TS = U
        self.TCP_TS_CNT = 1

        # define which probes to send
        self.PROBES_2_SEND = {
            'P1': 1,
            'P2': 1,
            'P3': 1,
            'P4': 1,
            'P5': 0,  # if no WIN and OPS probe test,  set to 0
            'P6': 0,  # if no WIN and OPS probe test,  set to 0
            'ECN': 0,
            'T2': 0,
            'T3': 0,
            'T4': 0,
            'T5': 1,
            'T6': 1,
            'T7': 1,
            'IE': 1,
            'U1': 1
        }

        # set TCP FLG
        self.TCP_FLAGS = {
            'SEQ': 'SA',
            'ECN': '0',
            # Y	set - 0x052 = ECE, SYN
            # N	set - 0x02  = SYN
            # S	set - 0x0C2 = CWR, ECE, SYN
            # O	set - 0x052 = CWR, SYN
            'T2': 0,
            'T3': 0,
            'T4': 0,
            'T5': 'RA',
            'T6': 'R',
            'T7': 'RA'
        }

        # TCP Sequence Number
        # A+, A, 0 = Z, O = something else
        self.TCP_SEQ_NR = {
            'T2': 0,
            'T3': 0,
            'T4': 0,
            'T5': 0,
            'T6': 'A',
            'T7': 0
        }

        # TCP Acknowledgment Number
        # S+, S, 0 = Z,  O = something else
        self.TCP_ACK_NR = {
            'T2': 0,
            'T3': 0,
            'T4': 0,
            'T5': 'S+',
            'T6': 0,
            'T7': 'S'
        }

        # Set TCP Options, Window Size, IP DF-bit and TCP data
        self.O_W_DF_RD_PARAM = {
            'P1': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'P2': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'P3': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'P4': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'P5': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'P6': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'ECN': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T2': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T3': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T4': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T5': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T6': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'T7': {'O': 0, 'W': 0, 'DF': 0, 'RD': 0},
            'U1': {'DF': 0},
            'IE': {'DF': 0}
        }

        # U1 probe (UDP)
        # Clear data from UDP reply
        self.CL_UDP_DATA = 1
        # Set normally unused, second 4 bytes of ICMP header
        self.UN = 0

        # IE probe
        # 0 =^ Z
        # S =^ same as from probes
        self.ICMP_CODE = 'S'

    @property
    def ISR_mean(self):
        return (self.ISR_MIN + self.ISR_MAX) / 2

    @property
    def SEQNr_mean(self):
        if self.GCD > 9:
            return self.GCD
        else:
            return math.trunc(round((2 ** (self.ISR_mean/8))*0.1))

    @property
    def SP_mean(self):
        return (self.SP_MIN + self.SP_MAX) / 2

    @property
    def SEQ_std_dev(self):
        return math.trunc(round((2 ** (self.SP_mean/8))))

    @property
    def SEQ_MIN(self):
        _SEQ_MIN = math.trunc(round((2 ** (self.ISR_MIN/8))*0.1))
        _SEQ_MIN -= (self.SEQ_std_dev/8)
        return _SEQ_MIN

    @property
    def SEQ_MAX(self):
        _SEQ_MAX = math.trunc(round((2 ** (self.ISR_MAX/8))*0.1))
        _SEQ_MAX += (self.SEQ_std_dev/8)
        return _SEQ_MAX


def flush_tables():
    os.system('iptables -F')


def _build_crc_tables(crc32_table, crc32_reverse):
    """
    Reverse CRC32 creation
    Used for TCP Replies with specific payload to be returned
    ----------------------------------------------------------
    https://github.com/StalkR/misc/blob/master/crypto/crc32.py
    """
    for i in range(256):
        fwd = i
        rev = i << 24
        for j in range(8, 0, -1):
            # build normal table
            if (fwd & 1) == 1:
                fwd = (fwd >> 1) ^ 0xedb88320
            else:
                fwd >>= 1
            crc32_table[i] = fwd
            # build reverse table =)
            if rev & 0x80000000 == 0x80000000:
                rev = ((rev ^ 0xedb88320) << 1) | 1
            else:
                rev <<= 1
            crc32_reverse[i] = rev

    return crc32_table, crc32_reverse


def crc32(s, crc32_table):
    crc = 0xffffffff
    for c in s:
        crc = (crc >> 8) ^ crc32_table[crc & 0xff ^ ord(c)]
    return crc ^ 0xffffffff


def reverse_crc(wanted_crc):
    s = " "
    pos = len(s)
    crc32_table, crc32_reverse = [0] * 256, [0] * 256
    crc32_table, crc32_reverse = _build_crc_tables(crc32_table, crc32_reverse)

    # forward calculation of CRC up to pos, sets current forward CRC state
    fwd_crc = 0xffffffff
    for c in s[:pos]:
        fwd_crc = (fwd_crc >> 8) ^ crc32_table[fwd_crc & 0xff ^ ord(c)]

    # backward calculation of CRC up to pos, sets wanted backward CRC state
    bkd_crc = wanted_crc ^ 0xffffffff
    for c in s[pos:][::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ crc32_reverse[bkd_crc >> 24]
        bkd_crc ^= ord(c)

    # deduce the 4 bytes we need to insert
    for c in struct.pack('<L', fwd_crc)[::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ crc32_reverse[bkd_crc >> 24]
        bkd_crc ^= ord(c)

    res = s[:pos] + struct.pack('<L', bkd_crc) + s[pos:]

    assert(crc32(res, crc32_table) == wanted_crc)
    return res


class ReplyPacket(object):
    """
    IP packet
    Setting the IP fields
    """
    def __init__(self, pkt, os_pattern):
        self.ip = IP()
        self.ip.src = pkt[IP].dst
        self.ip.dst = pkt[IP].src
        self.os_pattern = os_pattern
        self.ip.ttl = self.os_pattern.TTL

    def set_DF(self, df):
        if df:
            self.ip.flags = 'DF'

    def set_ToS(self, tos):
        self.ip.tos = tos

    # set IP ID according to the OS pattern
    def set_IP_ID(self, ip_id):

        if ip_id == 'I':
            self.os_pattern.IP_ID_tmp += 1
            self.ip.id = self.os_pattern.IP_ID_tmp

        elif ip_id == 'RI':
            self.os_pattern.IP_ID_tmp += 1001
            self.ip.id = self.os_pattern.IP_ID_tmp

        elif ip_id == 'Z':
            self.os_pattern.IP_ID_tmp += 0
            self.ip.id = self.os_pattern.IP_ID_tmp
        else:
            self.ip.id = ip_id


class TCPPacket(ReplyPacket):
    """
    TCP packet
    ----------------------------------------------------------
    setting the TCP fields
    """
    def __init__(self, pkt, os_pattern):
        ReplyPacket.__init__(self, pkt, os_pattern)
        self.pkt = pkt
        self.tcp = TCP()
        self.tcp.sport = pkt[TCP].dport
        self.tcp.dport = pkt[TCP].sport

    def set_TCP_Flags(self, flags):
        # set TCP header fields
        self.tcp.flags = flags

    def set_TCP_Options(self, options):
        self.tcp.options = options

    def set_IN_SEQ_NR(self, seqn):
        # set the initial SQNR
        if seqn == 'O':
            # The function of the calculation of the TCP Sequence Number belongs to honed
            # https://github.com/DataSoft/Honeyd/blob/master/personality.c   -  line 521 ff

            if 0 < self.os_pattern.GCD < 9:
                temp = random.randint(0, self.os_pattern.SEQ_std_dev)

                ISN_delta = self.os_pattern.SEQNr_mean

                while (self.os_pattern.SEQ_MAX < (self.os_pattern.SEQNr_mean + temp)) or \
                        (self.os_pattern.SEQ_MIN > (self.os_pattern.SEQNr_mean + temp)):
                    temp = random.randint(0, self.os_pattern.SEQ_std_dev)

                ISN_delta += temp

                self.os_pattern.TCP_SEQ_NR_tmp = (self.os_pattern.TCP_SEQ_NR_tmp + ISN_delta) % 2**32
                self.tcp.seq = self.os_pattern.TCP_SEQ_NR_tmp

            else:
                self.os_pattern.TCP_SEQ_NR_tmp = (self.os_pattern.TCP_SEQ_NR_tmp + self.os_pattern.SEQNr_mean) % 2**32
                self.tcp.seq = self.os_pattern.TCP_SEQ_NR_tmp

        elif seqn == 'A':
            self.tcp.seq = self.pkt[TCP].ack

        elif seqn == 'A+':
            self.tcp.seq = self.pkt[TCP].ack + 1

        else:
            self.tcp.seq = seqn

    # set ack number
    def set_ACK_NR(self, ack):
        self.tcp.ack = ack

        # to SEQNr + 1
        if ack == 'S':
            self.tcp.ack = self.pkt[TCP].seq
        # to the SEQNr of the probe
        elif ack == 'S+':
            self.tcp.ack = self.pkt[TCP].seq + 1
        # to a random value
        elif ack == 'O':
            self.tcp.ack = random.randint(1, 10)
        else:
            self.tcp.ack = ack

    # set window size
    def set_WSZ(self, winsz):
        self.tcp.window = winsz

    # set data
    # (Some operating systems return ASCII data such as error messages in reset packets.)
    def set_TCP_data(self, rd):
        if rd:
            self.tcp.payload = reverse_crc(rd)

    # send TCP packet on wire
    def send_packet(self):
        # print "Sending back a faked reply(TCP) to %s" % self.ip.dst
        send(self.ip/self.tcp, verbose=0)


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
        send(self.ip/self.icmp/self.data, verbose=0)

    # port unreachable
    def send_PUR_packet(self):
            send(self.ip/self.icmp/self.pkt, verbose=0)


def send_TCP_reply(pkt, os_pattern, O_W_DF_RD_PARAM, flags, ipid=0, seqn='O', ack='S+'):
    """
    Send TCP reply packet
    following parameter are optional: ipid, seqn, ack,
    """
    # create reply packet and set flags
    tcp_rpl = TCPPacket(pkt, os_pattern)

    # set flags depending on probe given
    tcp_rpl.set_TCP_Flags(flags)

    # set/adjust special header fields
    tcp_rpl.set_DF(O_W_DF_RD_PARAM['DF'])
    tcp_rpl.set_IN_SEQ_NR(seqn)
    tcp_rpl.set_ACK_NR(ack)
    tcp_rpl.set_WSZ(O_W_DF_RD_PARAM['W'])
    tcp_rpl.set_IP_ID(ipid)

    # set TCP options if needed
    if O_W_DF_RD_PARAM['O']:
        tcp_rpl.set_TCP_Options(O_W_DF_RD_PARAM['O'])

    # set TCP data
    if O_W_DF_RD_PARAM['RD']:
        tcp_rpl.set_TCP_data(O_W_DF_RD_PARAM['RD'])

    # send the TCP packet
    tcp_rpl.send_packet()


def send_ICMP_reply(pkt, ICMP_type, os_pattern, O_W_DF_RD_PARAM):
    """
    Send ICMP reply packet
    """
    # create reply packet and set flags
    icmp_rpl = ICMPPacket(pkt, os_pattern, ICMP_type)

    # set ICMP header fields
    icmp_rpl.set_DF(O_W_DF_RD_PARAM['DF'])

    # ICMP type = 0  =^ echo reply
    if ICMP_type == 0:
        icmp_rpl.set_IP_ID(os_pattern.IP_ID_II_CNT)
        # set ICMP code field
        if os_pattern.ICMP_CODE == 'S':
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

        # send ICMP Port Unreachable
        icmp_rpl.send_PUR_packet()


def forward_packet(nfq_packet):
    # send the packet from NFQUEUE without modification
    nfq_packet.set_verdict(nfqueue.NF_ACCEPT)


def drop_packet(nfq_packet):
    # drop the packet from NFQUEUE
    nfq_packet.set_verdict(nfqueue.NF_DROP)


def check_TCP_Nmap_match(pkt, nfq_packet, options_2_cmp, TCP_wsz_flags, IP_flags="no", urgt_ptr=0):
    """
    Check if the packet is a Nmap probe
    IPflags and urgt_ptr are optional
    return 1 if packet is a Nmap probe
    """
    if pkt[TCP].window == TCP_wsz_flags['WSZ'] and pkt[TCP].flags == TCP_wsz_flags['FLGS'] and pkt[TCP].options == options_2_cmp:
        if IP_flags == "no":
            if urgt_ptr == 0:
                drop_packet(nfq_packet)
                return 1
            elif pkt[TCP].urgptr == ECN_URGT_PTR:
                drop_packet(nfq_packet)
                return 1
        elif pkt[IP].flags == IP_flags['FLGS']:
            drop_packet(nfq_packet)
            return 1
    return 0


def check_TCP_probes(pkt, nfq_packet, os_pattern):
    # Check TCP Probes

    # calculate Timestamp for TCP header
    os_pattern.TCP_Timestamp_tmp += os_pattern.TCP_TS_CNT

    # Check if the packet is a probe and if a reply should be sent

    # SEQ, OPS, WIN, and T1 - Sequence generation
    # 6 Probes sent
    if check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P1'], NMAP_PROBE_TCP_ATTR['P1']):
        if os_pattern.PROBES_2_SEND['P1']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P1'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #1"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P2'], NMAP_PROBE_TCP_ATTR['P2']):
        if os_pattern.PROBES_2_SEND['P2']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P2'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #2"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P3'], NMAP_PROBE_TCP_ATTR['P3']):
        if os_pattern.PROBES_2_SEND['P3']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P3'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #3"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P4'], NMAP_PROBE_TCP_ATTR['P4']):
        if os_pattern.PROBES_2_SEND['P4']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P4'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #4"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P5'], NMAP_PROBE_TCP_ATTR['P5']):
        if os_pattern.PROBES_2_SEND['P5']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P5'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #5"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P6'], NMAP_PROBE_TCP_ATTR['P6']):
        if os_pattern.PROBES_2_SEND['P6']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['P6'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            print "TCP Probe #6"

    # ECN
    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['ECN'], NMAP_PROBE_TCP_ATTR['ECN'], ):
        if os_pattern.PROBES_2_SEND['ECN']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['ECN'], os_pattern.TCP_FLAGS['ECN'], os_pattern.IP_ID_TI_CNT, ECN_URGT_PTR)
            print "TCP Probe #ECN"

    # T2-T7
    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T2'], NMAP_PROBE_IP_ATTR['T2']):
        if os_pattern.PROBES_2_SEND['T2']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T2'], os_pattern.TCP_FLAGS['T2'], 0, os_pattern.TCP_SEQ_NR['T2'], os_pattern.TCP_ACK_NR['T2'])
            print "TCP Probe #T2"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T3']):
        if os_pattern.PROBES_2_SEND['T3']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T3'], os_pattern.TCP_FLAGS['T3'], 0, os_pattern.TCP_SEQ_NR['T3'], os_pattern.TCP_ACK_NR['T3'])
            print "TCP Probe #T3"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T4'], NMAP_PROBE_IP_ATTR['T4']):
        if os_pattern.PROBES_2_SEND['T4']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T4'], os_pattern.TCP_FLAGS['T4'], 0, os_pattern.TCP_SEQ_NR['T4'], os_pattern.TCP_ACK_NR['T4'])
            print "TCP Probe #T4"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T5']):
        if os_pattern.PROBES_2_SEND['T5']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T5'], os_pattern.TCP_FLAGS['T5'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T5'], os_pattern.TCP_ACK_NR['T5'])
            print "TCP Probe #T5"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T6'], NMAP_PROBE_IP_ATTR['T6']):
        if os_pattern.PROBES_2_SEND['T6']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T6'], os_pattern.TCP_FLAGS['T6'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T6'], os_pattern.TCP_ACK_NR['T6'])
            print "TCP Probe #T6"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T7'], NMAP_PROBE_TCP_ATTR['T7']):
        if os_pattern.PROBES_2_SEND['T7']:
            send_TCP_reply(pkt, os_pattern, os_pattern.O_W_DF_RD_PARAM['T7'], os_pattern.TCP_FLAGS['T7'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T7'], os_pattern.TCP_ACK_NR['T7'])
            print "TCP Probe #T7"
    else:
        forward_packet(nfq_packet)


def check_ICMP_probes(pkt, nfq_packet, os_pattern):
    """
    Identify the ICMP based probes
    and reply with a faked packet if needed
    """
    if pkt[ICMP].type is 8:

        # Probe 1 + 2
        if (pkt[ICMP].seq == 295 and pkt[IP].flags == 0x02 and len(pkt[ICMP].payload) == 120) or (pkt[ICMP].seq == 296 and pkt[IP].tos == 0x04 and len(pkt[ICMP].payload) == 150):
            drop_packet(nfq_packet)

            if os_pattern.PROBES_2_SEND["IE"]:
                # ICMP type = 0  =^ echo reply
                ICMP_type = 0
                send_ICMP_reply(pkt, ICMP_type, os_pattern, os_pattern.O_W_DF_RD_PARAM['IE'])
                print "IE Probe"
        else:
            forward_packet(nfq_packet)
    else:
        forward_packet(nfq_packet)


def check_UDP_probe(pkt, nfq_packet,  os_pattern):
    """
    Identify the UDP based probe
    and reply with a faked reply if needed
    """
    if pkt[IP].id == 0x1042 and pkt[UDP].payload.load[0] == "C" and pkt[UDP].payload.load[1] == "C" and pkt[UDP].payload.load[2] == "C":
        drop_packet(nfq_packet)

        if os_pattern.PROBES_2_SEND["U1"]:
            # create reply packet (ICMP port unreachable)
            # ICMP type = 3  =^ destination unreable
            ICMP_type = 3
            send_ICMP_reply(pkt, ICMP_type, os_pattern, os_pattern.O_W_DF_RD_PARAM['U1'])
            print "U1 Probe"
    else:
        forward_packet(nfq_packet)


class ProcessPKT(object):
    """
    Do a separation according to the TCP/IP trasport layer
    check if the packet is a nmap probe and send OS specific replies
    """
    def __init__(self, os_pattern):
        self.os_pattern = os_pattern

    def callback(self, _, nfq_packet):
        # Get packetdata from nfqueue packet and build a Scapy packet
        pkt = IP(nfq_packet.get_data())

        # check TCP packets
        if pkt.haslayer(TCP):
            check_TCP_probes(pkt, nfq_packet, self.os_pattern)

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
    def run(cls, template_path=''):

        # check if root
        if not os.geteuid() == 0:
            exit("\nPlease run as root\n")
        os_pattern = get_os_pattern(template_path)

        # Flush the IP tables first
        flush_tables()
        # Configure NFQUEUE target
        # Capture incoming packets and put in nfqueue 1
        os.system('iptables -A INPUT -j NFQUEUE --queue-num 0')

        # creation of a new queue object
        q = nfqueue.queue()
        q.set_callback(ProcessPKT(os_pattern).callback)
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
            print 'Exiting...'


if __name__ == '__main__':
    OSFuscation.run()
