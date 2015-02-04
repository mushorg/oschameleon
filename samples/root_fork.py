import gevent.monkey
gevent.monkey.patch_all()

import os
import pwd
import grp

import gevent
import oschameleon.osfuscation


def root_process():
    print("Child running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
    oschameleon.osfuscation.OSFuscation.run()


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    print("Running as {0}/{1}.".format(pwd.getpwuid(os.getuid())[0], grp.getgrgid(os.getgid())[0]))
    wanted_uid = pwd.getpwnam(uid_name)[2]
    wanted_gid = grp.getgrnam(gid_name)[2]

    pid = gevent.fork()
    if pid == 0:
        os.setgid(wanted_gid)
        os.setuid(wanted_uid)
        new_uid_name = pwd.getpwuid(os.getuid())[0]
        new_gid_name = grp.getgrgid(os.getgid())[0]
        print("Privileges dropped, running as {0}/{1}.".format(new_uid_name, new_gid_name))
    else:
        lets = gevent.spawn(root_process)
        gevent.joinall([lets, ])


if __name__ == '__main__':
    try:
        drop_privileges()
    except KeyboardInterrupt:
        print "bye"
