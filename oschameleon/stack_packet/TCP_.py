#!/usr/bin/python
'''
Created on 24.09.2016

@author: manuel
'''

import random

from IP_ import ReplyPacket
from IP_ import reverse_crc
from helper import drop_packet
from helper import forward_packet
from scapy.all import IP, TCP, send  # @UnresolvedImport 


# Flags in IP Header
# 0x02 ^= DF-Bit
NMAP_PROBE_IP_ATTR = {
    'T2': {'FLGS': 0x02},
    'T4': {'FLGS': 0x02},
    'T6': {'FLGS': 0x02}
}

# TCP Urgent Pointer in ECN probe
ECN_URGT_PTR = 0xF7F5

# The TCP Option fields in the Nmap probes
NMAP_PROBE_TCP_OPTION = {'P1': [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (4294967295, 0)), ('SAckOK', '')],
                         'P2': [('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('EOL', None)],
                         'P3': [('Timestamp', (4294967295, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)],
                         'P4': [('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)],
                         'P5': [('MSS', 536), ('SAckOK', ''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)],
                         'P6': [('MSS', 265), ('SAckOK', ''), ('Timestamp', (4294967295, 0))],
                         'ECN': [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('NOP', None)],
                         'T2-T6': [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', '')],
                         'T7': [('WScale', 15), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', '')]
                         }

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

                self.os_pattern.TCP_SEQ_NR_tmp = (self.os_pattern.TCP_SEQ_NR_tmp + ISN_delta) % 2 ** 32
                self.tcp.seq = self.os_pattern.TCP_SEQ_NR_tmp

            else:
                self.os_pattern.TCP_SEQ_NR_tmp = (self.os_pattern.TCP_SEQ_NR_tmp + self.os_pattern.SEQNr_mean) % 2 ** 32
                self.tcp.seq = (self.os_pattern.TCP_SEQ_NR_tmp)

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
        # self.tcp.show()
        # print "-"*10
        # print self.tcp.getlayer('TCP').options
        send(self.ip / self.tcp, verbose=0)


def check_TCP_Nmap_match(pkt, nfq_packet, INPUT_TCP_OPTIONS, EXPECTED_TCP_flags, IP_flags="no", urgt_ptr=0):
    """
    Check if the packet is a Nmap probe
    IPflags and urgt_ptr are optional
    return 1 if packet is a Nmap probe
    """
    # print pkt[TCP]
    if pkt[TCP].window == EXPECTED_TCP_flags['WSZ'] and pkt[TCP].flags == EXPECTED_TCP_flags['FLGS'] and pkt[TCP].options == INPUT_TCP_OPTIONS:

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


def send_TCP_reply(pkt, os_pattern, TCP_OPTIONS, flags, ipid=0, seqn='O', ack='S+'):
    """
    Send TCP reply packet
    following parameter are optional: ipid, seqn, ack,
    """
    # create reply packet and set flags
    tcp_rpl = TCPPacket(pkt, os_pattern)

    # set flags depending on probe given
    tcp_rpl.set_TCP_Flags(flags)

    # set/adjust special header fields
    tcp_rpl.set_DF(TCP_OPTIONS['DF'])
    tcp_rpl.set_IN_SEQ_NR(seqn)
    tcp_rpl.set_ACK_NR(ack)
    tcp_rpl.set_WSZ(TCP_OPTIONS['W'])
    tcp_rpl.set_IP_ID(ipid)

    # set TCP options if needed
    if TCP_OPTIONS['O']:
        # calculate Timestamp for TCP header
        os_pattern.TCP_Timestamp_tmp += os_pattern.TCP_TS_CNT
        # print os_pattern.TCP_Timestamp_tmp
        # time = int(os_pattern.TCP_Timestamp_tmp)

        tsver = 0
        for ele in pkt[TCP].options:
            if ele[0] == "Timestamp":
                tsver = ele[1][0]

        tcp_rpl.set_TCP_Options(TCP_OPTIONS['O'] + [('Timestamp', (int(str(os_pattern.TCP_Timestamp_tmp), 10), tsver))])

    # set TCP data
    if TCP_OPTIONS['RD']:
        tcp_rpl.set_TCP_data(TCP_OPTIONS['RD'])

    # send the TCP packet
    tcp_rpl.send_packet()


def check_in_session(session, ip, debug):
    session.in_session(ip, debug)


def check_TCP_probes(pkt, nfq_packet, os_pattern, session, debug):
    # Check TCP Probes

    # Check if the packet is a probe and if a reply should be sent

    # SEQ, OPS, WIN, and T1 - Sequence generation
    # 6 Probes sent
    if check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P1'], NMAP_PROBE_TCP_ATTR['P1']):
        if os_pattern.PROBES_2_SEND['P1']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P1'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #1"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P2'], NMAP_PROBE_TCP_ATTR['P2']):
        if os_pattern.PROBES_2_SEND['P2']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P2'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #2"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P3'], NMAP_PROBE_TCP_ATTR['P3']):
        if os_pattern.PROBES_2_SEND['P3']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P3'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #3"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P4'], NMAP_PROBE_TCP_ATTR['P4']):
        if os_pattern.PROBES_2_SEND['P4']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P4'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #4"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P5'], NMAP_PROBE_TCP_ATTR['P5']):
        if os_pattern.PROBES_2_SEND['P5']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P5'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #5"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['P6'], NMAP_PROBE_TCP_ATTR['P6']):
        if os_pattern.PROBES_2_SEND['P6']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['P6'], os_pattern.TCP_FLAGS['SEQ'], os_pattern.IP_ID_TI_CNT)
            # print "TCP Probe #6"

    # ECN
    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['ECN'], NMAP_PROBE_TCP_ATTR['ECN'],):
        if os_pattern.PROBES_2_SEND['ECN']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['ECN'], os_pattern.TCP_FLAGS['ECN'], os_pattern.IP_ID_TI_CNT, ECN_URGT_PTR)
            # print "TCP Probe #ECN"

    # T2-T7
    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T2'], NMAP_PROBE_IP_ATTR['T2']):
        if os_pattern.PROBES_2_SEND['T2']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T2'], os_pattern.TCP_FLAGS['T2'], 0, os_pattern.TCP_SEQ_NR['T2'], os_pattern.TCP_ACK_NR['T2'])
            # print "TCP Probe #T2"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T3']):
        if os_pattern.PROBES_2_SEND['T3']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T3'], os_pattern.TCP_FLAGS['T3'], 0, os_pattern.TCP_SEQ_NR['T3'], os_pattern.TCP_ACK_NR['T3'])
            # print "TCP Probe #T3"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T4'], NMAP_PROBE_IP_ATTR['T4']):
        if os_pattern.PROBES_2_SEND['T4']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T4'], os_pattern.TCP_FLAGS['T4'], 0, os_pattern.TCP_SEQ_NR['T4'], os_pattern.TCP_ACK_NR['T4'])
            # print "TCP Probe #T4"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T5']):
        if os_pattern.PROBES_2_SEND['T5']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T5'], os_pattern.TCP_FLAGS['T5'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T5'], os_pattern.TCP_ACK_NR['T5'])
            # print "TCP Probe #T5"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T2-T6'], NMAP_PROBE_TCP_ATTR['T6'], NMAP_PROBE_IP_ATTR['T6']):
        if os_pattern.PROBES_2_SEND['T6']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T6'], os_pattern.TCP_FLAGS['T6'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T6'], os_pattern.TCP_ACK_NR['T6'])
            # print "TCP Probe #T6"

    elif check_TCP_Nmap_match(pkt, nfq_packet, NMAP_PROBE_TCP_OPTION['T7'], NMAP_PROBE_TCP_ATTR['T7']):
        if os_pattern.PROBES_2_SEND['T7']:
            check_in_session(session, pkt.src, debug)
            send_TCP_reply(pkt, os_pattern, os_pattern.TCP_OPTIONS['T7'], os_pattern.TCP_FLAGS['T7'], os_pattern.IP_ID_CI_CNT, os_pattern.TCP_SEQ_NR['T7'], os_pattern.TCP_ACK_NR['T7'])
            # print "TCP Probe #T7"

    else:
        forward_packet(nfq_packet)
