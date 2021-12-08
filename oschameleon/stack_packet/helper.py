#!/usr/bin/python

import nfqueue
import os


def flush_tables():
    os.system("iptables -F")


def forward_packet(nfq_packet):
    # send the packet from NFQUEUE without modification
    nfq_packet.set_verdict(nfqueue.NF_ACCEPT)


def drop_packet(nfq_packet):
    # drop the packet from NFQUEUE
    nfq_packet.set_verdict(nfqueue.NF_DROP)


def rules(server):
    # print server
    # allow incoming ssh
    os.system(
        "iptables -A INPUT -p tcp -s"
        + server
        + " --dport 63712 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d"
        + server
        + " --sport 63712 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing ssh
    os.system(
        "iptables -A OUTPUT -p tcp -d"
        + server
        + " --sport 63712 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s"
        + server
        + " --dport 63712 -m state --state ESTABLISHED -j ACCEPT"
    )

    # Configure NFQUEUE target
    # Capture incoming packets and put in nfqueue 1
    os.system("iptables -A INPUT -j NFQUEUE --queue-num 0")
