'''
Created on 01.12.2016

@author: manuel
'''
import argparse
import gevent.monkey
import grp
import os
import pwd
import sys

from osfuscation import OSFuscation
from session.log import Log
from stack_packet.helper import flush_tables


class OSChameleon(object):
    def __init__(self, template=None, template_directory=None, args=None):
        gevent.monkey.patch_all()

        self.parser = argparse.ArgumentParser(description='OSChameleon sample usage')
        self.parser.add_argument('--template', metavar='template.txt', type=str, help='path to the fingerprint template')
        self.parser.add_argument('--server', metavar='server ip for iptables', type=str, help='server ip for iptables')
        self.args = self.parser.parse_args()
        
        if self.args.template == None:
            self.args.template = "template/SIMATIC_300_PLC.txt"
  
        if self.args.server == None:
            print "\n define a server ip \n"
            sys.exit() 
        
        logger = Log("oschameleon")
        logger.info("init")
        
    
    def start(self):
        try:
            self.drop_privileges()
        except KeyboardInterrupt:
            flush_tables()
            print ("bye")
   

    def root_process(self):
        print("Child: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
        data = OSFuscation.run(self.args.template, self.args.server)
        print('OSFuscation return value', data)


    def drop_privileges(self, uid_name='nobody', gid_name='nogroup'):
        print("Init: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
        wanted_uid = pwd.getpwnam(uid_name)[2]
        wanted_gid = grp.getgrnam(gid_name)[2]

        pid = gevent.fork()
        # print "root_fork : drop_privil  :  pid   ",pid
        if pid == 0:
            # child
            print  ('starting child process')
            child_process = gevent.spawn(self.root_process)
            child_process.join()
            print  ('Child done:', child_process.successful())
            flush_tables()
            print  ('Child exit')
        else:
            # parent
            os.setgid(wanted_gid)
            os.setuid(wanted_uid)
            new_uid_name = pwd.getpwuid(os.getuid())[0]
            new_gid_name = grp.getgrgid(os.getgid())[0]
            print("Parent: Privileges dropped, running as {0}/{1}.".format(new_uid_name, new_gid_name))
            while True:
                try:
                    gevent.sleep(1)
                    # print ('Parent: ping')
                except KeyboardInterrupt:
                    break


if __name__ == '__main__':
    p = OSChameleon()
    p.start()

