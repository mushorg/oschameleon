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

**Note: This script flushes iptables before and after usage!**