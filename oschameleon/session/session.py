'''
Created on 02.12.2016

@author: manuel
'''

from datetime import datetime, timedelta
import logging
from ext_ip import Ext_IP

logger = logging.getLogger("oschameleon")

ext = Ext_IP()

class nmap_session(object):
    def __init__(self, ip, time):
        self.ip = ip
        self.time = time
        

class Session(object):
    def __init__(self):
        self.sessions = []
        self.my_ip = ext.get_ext_ip()
    
    def in_session(self, ip):
        currenttime = datetime.now()
        timeout = currenttime + timedelta(minutes=10)
        
        # if not self.sessions:
        #    #print "new"
        #    nsess = nmap_session(ip, currenttime)
        #    self.sessions.append(nsess)
        #    logger.info("%s : New session from %s at %s", currenttime, ip, self.my_ip)
        
        exists = False
        
        for session in self.sessions:
            if ip == session.ip:
                exists = True
                if currenttime > session.time:
                    session.time = timeout
                    logger.info('%s : Renewed session from %s at %s', currenttime, ip, self.my_ip)
                    print("renew  " + ip)
            
        if not exists:
            # print "added"
            nsess = nmap_session(ip, timeout)
            self.sessions.append(nsess)
            logger.info("%s : New session from %s  at %s", currenttime, ip, self.my_ip)
            print("new  " + ip)
                
            
            
