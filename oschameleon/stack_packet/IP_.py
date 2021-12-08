#!/usr/bin/python
"""
Created on 24.09.2016

@author: manuel
"""

import struct

from scapy.all import IP  # @UnresolvedImport


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
            self.ip.flags = "DF"

    def set_ToS(self, tos):
        self.ip.tos = tos

    # set IP ID according to the OS pattern
    def set_IP_ID(self, ip_id):

        if ip_id == "I":
            self.os_pattern.IP_ID_tmp += 1
            self.ip.id = self.os_pattern.IP_ID_tmp

        elif ip_id == "RI":
            self.os_pattern.IP_ID_tmp += 1001
            self.ip.id = self.os_pattern.IP_ID_tmp

        elif ip_id == "Z":
            self.os_pattern.IP_ID_tmp += 0
            self.ip.id = self.os_pattern.IP_ID_tmp
        else:
            self.ip.id = ip_id


# \ End of CONSTANTS
# ----------------------------------------------------------
# Change MAC Address
# ------------------
# 00:1C:06:FF:DE:A4       -   Siemens Numerical Control Ltd
# 00:1F:F8:FF:DE:A4    -   Siemens AG, Sector Industry
# 00:08:74            -   DELL
# 00:0C:29:6A:9C:C1  -   Vmware
#
# nmap mapping to vendors /usr/share/nmap/nmap-mac-prefixes
# os.system('ifconfig eth0 down')
# os.system('ifconfig eth0 hw ether 00:1F:F8:FF:DE:A4')
# os.system('ifconfig eth0 up')


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
                fwd = (fwd >> 1) ^ 0xEDB88320
            else:
                fwd >>= 1
            crc32_table[i] = fwd
            # build reverse table =)
            if rev & 0x80000000 == 0x80000000:
                rev = ((rev ^ 0xEDB88320) << 1) | 1
            else:
                rev <<= 1
            crc32_reverse[i] = rev

    return crc32_table, crc32_reverse


def crc32(s, crc32_table):
    crc = 0xFFFFFFFF
    for c in s:
        crc = (crc >> 8) ^ crc32_table[crc & 0xFF ^ ord(c)]
    return crc ^ 0xFFFFFFFF


def reverse_crc(wanted_crc):
    s = " "
    pos = len(s)
    crc32_table, crc32_reverse = [0] * 256, [0] * 256
    crc32_table, crc32_reverse = _build_crc_tables(crc32_table, crc32_reverse)

    # forward calculation of CRC up to pos, sets current forward CRC state
    fwd_crc = 0xFFFFFFFF
    for c in s[:pos]:
        fwd_crc = (fwd_crc >> 8) ^ crc32_table[fwd_crc & 0xFF ^ ord(c)]

    # backward calculation of CRC up to pos, sets wanted backward CRC state
    bkd_crc = wanted_crc ^ 0xFFFFFFFF
    for c in s[pos:][::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xFFFFFFFF) ^ crc32_reverse[bkd_crc >> 24]
        bkd_crc ^= ord(c)

    # deduce the 4 bytes we need to insert
    for c in struct.pack("<L", fwd_crc)[::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xFFFFFFFF) ^ crc32_reverse[bkd_crc >> 24]
        bkd_crc ^= ord(c)

    res = s[:pos] + struct.pack("<L", bkd_crc) + s[pos:]

    assert crc32(res, crc32_table) == wanted_crc
    return res
