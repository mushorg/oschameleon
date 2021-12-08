'''
Created on 24.09.2016

@author: manuel
'''


import math
import random


class OSPatternTemplate(object):
    """
    Defining the OS characteristics
    Take the values from the Nmap fingerprint
    """
    def __init__(self):
        # for TG probe
        self.TTL = 0x20

        # SEQ probes
        # GCD Greatest common divisor
        self.GCD = 0

        # ISR Initial SEQNr counter rate
        self.ISR_MIN = 0
        self.ISR_MAX = 0

        # SP (standard deviation of Initial SEQNr)
        self.SP_MIN = 0
        self.SP_MAX = 1

        # start value of SEQNR
        self.TCP_SEQ_NR_tmp = random.randint(1, 10)

        # TI - CI - II
        # difference of IP header ID fields by different response groups
        #  I (incremental)
        #  RI (random positive increments)
        #  BI (broken increment)
        self.IP_ID_TI_CNT = 'I'  # SEQ - TI field
        self.IP_ID_CI_CNT = 'I'  # T5-7 - CI field
        self.IP_ID_II_CNT = 'I'  # IE - II field
        self.IP_ID_tmp = 1

        # Timestamp in reply packets
        self.TCP_Timestamp_tmp = 1
        # Timestamp counter 1... if TS = U
        self.TCP_TS_CNT = 1

        # define which probes to send
        self.PROBES_2_SEND = {
            'P1': 0,  # 1
            'P2': 0,  # 1
            'P3': 0,  # 1
            'P4': 0,  # 1
            'P5': 0,  # if no WIN and OPS probe test,  set to 0
            'P6': 0,  # if no WIN and OPS probe test,  set to 0
            'ECN': 0,
            'T2': 0,
            'T3': 0,
            'T4': 0,
            'T5': 0,  # 1
            'T6': 0,  # 1
            'T7': 0,  # 1
            'IE': 0,  # 1
            'U1': 0   # 1
        }

        # set TCP FLG
        self.TCP_FLAGS = {
            'SEQ': 'SA',
            'ECN': 0,
            # Y    set - 0x052 = ECE, SYN
            # N    set - 0x02  = SYN
            # S    set - 0x0C2 = CWR, ECE, SYN
            # O    set - 0x052 = CWR, SYN
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

        self.TCP_Timestamp = {
            'P1': {'tsval': 0, 'tsver': 0},
            'P2': {'tsval': 0, 'tsver': 0},
            'P3': {'tsval': 0, 'tsver': 0},
            'P4': {'tsval': 0, 'tsver': 0},
            'P5': {'tsval': 0, 'tsver': 0},
            'P6': {'tsval': 0, 'tsver': 0},
            'ECN': {'tsval': 0, 'tsver': 0},
            'T2': {'tsval': 0, 'tsver': 0},
            'T3': {'tsval': 0, 'tsver': 0},
            'T4': {'tsval': 0, 'tsver': 0},
            'T5': {'tsval': 0, 'tsver': 0},
            'T6': {'tsval': 0, 'tsver': 0},
            'T7': {'tsval': 0, 'tsver': 0},
            'U1': {'tsval': 0, 'tsver': 0},
            'IE': {'tsval': 0, 'tsver': 0}
        }

        # Set TCP Options, Window Size, IP DF-bit and TCP data
        self.TCP_OPTIONS = {
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

        self.time_div = 0.1

        # IPL = IP total length
        self.ICMP_IPL = 0

    @property
    def ISR_mean(self):
        # return (int(self.ISR_MIN,16) + int(self.ISR_MAX,16)) / 2
        return (self.ISR_MIN + self.ISR_MAX) / 2

    @property
    def SEQNr_mean(self):
        if self.GCD > 9:
            return self.GCD
        else:
            return math.trunc(round((2 ** (self.ISR_mean / 8)) * self.time_div))

    @property
    def SP_mean(self):
        return (self.SP_MIN + self.SP_MAX) / 2

    @property
    def SEQ_std_dev(self):
        return math.trunc(round((2 ** (self.SP_mean / 8))))

    @property
    def SEQ_MIN(self):
        _SEQ_MIN = math.trunc(round((2 ** (self.ISR_MIN / 8)) * self.time_div))
        _SEQ_MIN -= (self.SEQ_std_dev / 8)
        return _SEQ_MIN

    @property
    def SEQ_MAX(self):
        _SEQ_MAX = math.trunc(round((2 ** (self.ISR_MAX / 8)) * self.time_div))
        _SEQ_MAX += (self.SEQ_std_dev / 8)
        return _SEQ_MAX

    def __str__(self):
        for elem in self.TCP_Timestamp:
            timestamp = elem
            timestamp = timestamp + "  " + str(self.TCP_Timestamp[elem])
            print(timestamp)

        return ' TTL: ' + str(self.TTL) + \
               '\t\t\t GCD: ' + str(self.GCD) + \
               '\t\t\t ISR_MIN: ' + str(self.ISR_MIN) + \
               '\t\t\t ISR_MAX: ' + str(self.ISR_MAX) + \
               '\n SP_MIN: ' + str(self.SP_MIN) + \
               '\t\t\t SP_MAX: ' + str(self.SP_MAX) + \
               '\t\t\t TCP_SEQ_NR_tmp: ' + str(self.TCP_SEQ_NR_tmp) + \
               '\n IP_ID_TI_CNT: ' + str(self.IP_ID_TI_CNT) + \
               '\t\t IP_ID_CI_CNT: ' + str(self.IP_ID_CI_CNT) + \
               '\t\t IP_ID_II_CNT: ' + str(self.IP_ID_II_CNT) + \
               '\t\t IP_ID_tmp: ' + str(self.IP_ID_tmp) + \
               '\n TCP_Timestamp_tmp: ' + str(self.TCP_Timestamp_tmp) + \
               '\t\t TCP_TS_CNT: ' + str(self.TCP_TS_CNT) + \
               '\n PROBES_2_SEND: ' + str(self.PROBES_2_SEND) + \
               '\n TCP_FLAGS: \t' + str(self.TCP_FLAGS) + \
               '\n TCP_SEQ_NR: \t' + str(self.TCP_SEQ_NR) + \
               '\n TCP_ACK_NR: \t' + str(self.TCP_ACK_NR) + \
               '\n TCP_OPTIONS: \t P1' + str(self.TCP_OPTIONS['P1']) + \
               '\t\t P2' + str(self.TCP_OPTIONS['P2']) + \
               '\t\t P3' + str(self.TCP_OPTIONS['P3']) + \
               '\n \t\t P4' + str(self.TCP_OPTIONS['P4']) + \
               '\t\t P5' + str(self.TCP_OPTIONS['P5']) + \
               '\t\t P6' + str(self.TCP_OPTIONS['P6']) + \
               '\n \t\t ECN' + str(self.TCP_OPTIONS['ECN']) + \
               '\t\t T2' + str(self.TCP_OPTIONS['T2']) + \
               '\t\t T3' + str(self.TCP_OPTIONS['T3']) + \
               '\n \t\t T4' + str(self.TCP_OPTIONS['T4']) + \
               '\t\t T5' + str(self.TCP_OPTIONS['T5']) + \
               '\t\t T6' + str(self.TCP_OPTIONS['T6']) + \
               '\n \t\t T7' + str(self.TCP_OPTIONS['T7']) + \
               '\t\t U1' + str(self.TCP_OPTIONS['U1']) + \
               '\t\t\t\t\t IE' + str(self.TCP_OPTIONS['IE']) + \
               '\n CL_UDP_DATA: ' + str(self.CL_UDP_DATA) + \
               '\t\t\t UN: ' + str(self.UN) + \
               '\t\t\t\t ICMP_CODE: ' + str(self.ICMP_CODE) + \
               '\t\t\t ICMP_IPL: ' + str(self.ICMP_IPL)
