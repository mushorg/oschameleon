'''
Created on 02.12.2016

@author: manuel
'''

from datetime import datetime, timedelta
import logging
from ext_ip import Ext_IP
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni

logger = logging.getLogger("oschameleon")

ext = Ext_IP()


class nmap_session(object):
    def __init__(self, ip, time):
        self.ip = ip
        self.time = time


class Session(object):
    def __init__(self):
        self.sessions = []

    def externalIP(self, public, interface):
        if public is True:
            self.my_ip = ext.get_ext_ip()
        else:
            self.my_ip = ni.ifaddresses(interface)[AF_INET][0]['addr']

    def in_session(self, ip, debug):
        currenttime = datetime.now()
        currenttimestring = currenttime.strftime("%Y-%m-%d %H:%M:%S")
        timeout = currenttime + timedelta(minutes=10)

        exists = False

        for session in self.sessions:
            if ip == session.ip:
                exists = True
                if currenttime > session.time:
                    session.time = timeout
                    logger.info('%s : Renewed session from %s at %s', currenttimestring, ip, self.my_ip)
                    if debug:
                        print("renew  " + ip)

        if not exists:
            # print "added"
            nsess = nmap_session(ip, timeout)
            self.sessions.append(nsess)
            logger.info("%s : New session from %s  at %s", currenttimestring, ip, self.my_ip)
            if debug:
                print("new  " + ip)
