.. image:: https://travis-ci.org/mushorg/oschameleon.svg?branch=master
    :target: https://travis-ci.org/mushorg/oschameleon

===========
OSChameleon
===========

| **OS Fingerprint Obfuscation for modern Linux  Kernels.**
| *Author: Anton Hinterleitner is111012@fhstp.ac.at*

Description: Fools the probes of nmap scanner

Prerequisites: 
 * Linux (tested with Debian)
 * Python 2.6+
 * python-nfqueue=0.5-1+b1 (apt-get install python-nfqueue)
 * python-scapy=2.2.0-1
 * python-gevent=1.0.1-2
 * python-netifaces

Recorded logs are stored to:
    /var/log/honeypot/

Usage:
    python2.7 oschameleonRun.py 
        --template      path to the nmap fingerprint, either absolute or relative to the execution folder
        --server        sets an exception for the iptables to access over ssh. the ssh port should either be changed to 63712 or the port number in stack_packet/helper.py
        --public_ip     either fetches the server public ip or gets the ip set for the interface
        --interface     the network interface
        --debug         debugging output


**Note: This script flushes iptables before and after usage!**
