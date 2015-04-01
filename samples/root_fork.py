# Copyright (c) 2015 Lukas Rist

import gevent.monkey
gevent.monkey.patch_all()

import os
import pwd
import grp
import argparse

import gevent
import oschameleon.osfuscation


def root_process():
    print("Child: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
    data = oschameleon.osfuscation.OSFuscation.run(args.template)
    print 'OSFuscation return value', data


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    print("Init: Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
    wanted_uid = pwd.getpwnam(uid_name)[2]
    wanted_gid = grp.getgrnam(gid_name)[2]

    pid = gevent.fork()
    if pid == 0:
        # child
        print 'starting child process'
        child_process = gevent.spawn(root_process)
        child_process.join()
        print 'Child done:', child_process.successful()
        oschameleon.osfuscation.flush_tables()
        print 'Child exit'
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
                print 'Parent: ping'
            except KeyboardInterrupt:
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OSChameleon sample usage')
    parser.add_argument('--template', metavar='template.txt', type=str, help='path to the fingerprint template')
    args = parser.parse_args()
    try:
        drop_privileges()
    except KeyboardInterrupt:
        oschameleon.osfuscation.flush_tables()
        print "bye"
