'''
Created on 01.12.2016

@author: manuel
'''
import argparse
import gevent.monkey
import grp
import os
import pwd

from osfuscation import OSFuscation
from session.log import Log
import session
from stack_packet.helper import flush_tables

Log("oschameleon")


class OSChameleon(object):
    def __init__(self, template=None, template_directory=None, args=None):
        self.parser = argparse.ArgumentParser(description='OSChameleon sample usage')
        self.parser.add_argument('--template', metavar='template/SIMATIC_300_PLC.txt', type=str, help='path to the nmap fingerprint template', default="template/SIMATIC_300_PLC.txt")
        self.parser.add_argument('--server', metavar='IP', type=str, help='server ip for iptables', default='127.0.0.1')
        self.parser.add_argument('--public_ip', metavar='IP', help='running in production with public ip', default=False)
        self.parser.add_argument('--interface', metavar='eth0', help='network interface', default='eth0')
        self.parser.add_argument('--debug', metavar='True/False', help='verbose debugging output', default=False)
        self.args = self.parser.parse_args()

        gevent.monkey.patch_all()

        if self.args.debug == 'True':
            self.args.debug = True
        else:
            self.args.debug = False

        if self.args.debug:
            print("OSChameleon starting with: " + self.args.template)

        session.get_Session().externalIP(self.args.public_ip, self.args.interface)

    def start(self):
        try:
            self.drop_privileges()
        except KeyboardInterrupt:
            flush_tables()
            print ("bye")

    def root_process(self):
        if self.args.debug:
            print("Child: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
        data = OSFuscation.run(self.args.public_ip, self.args.debug, self.args.template, self.args.server)
        if self.args.debug:
            print('OSFuscation return value', data)

    def drop_privileges(self, uid_name='nobody', gid_name='nogroup'):
        if self.args.debug:
            print("Init: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
        wanted_uid = pwd.getpwnam(uid_name)[2]
        wanted_gid = grp.getgrnam(gid_name)[2]

        pid = gevent.fork()
        # print "root_fork : drop_privil  :  pid   ",pid
        if pid == 0:
            # child
            # print  ('starting child process')
            child_process = gevent.spawn(self.root_process)
            child_process.join()
            # print  ('Child done:', child_process.successful())
            flush_tables()
            # print  ('Child exit')
        else:
            # parent
            os.setgid(wanted_gid)
            os.setuid(wanted_uid)
            new_uid_name = pwd.getpwuid(os.getuid())[0]
            new_gid_name = grp.getgrgid(os.getgid())[0]
            if self.args.debug:
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
