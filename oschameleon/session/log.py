'''
Created on 02.12.2016

@author: manuel
'''

import logging.handlers
import os


logger = logging.getLogger("oschameleon")


class Log(object):
    def __init__(self, name):
        self.setup(name)

    def setup(self, name):
        # self.remote_logging(name, server)
        self.py_logging(name)

    def folder_exist(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def remote_logging(self, name, server):
        rootLogger = logging.getLogger('')
        rootLogger.setLevel(logging.DEBUG)
        print server
        socketHandler = logging.handlers.SocketHandler(server, logging.handlers.DEFAULT_TCP_LOGGING_PORT)
        # don't bother with a formatter, since a socket handler sends the event as
        # an unformatted pickle
        rootLogger.addHandler(socketHandler)

    def py_logging(self, name):
        # print ("log", name)
        path = "/var/log/honeypot/"
        self.folder_exist(path)
        logFile = path + name + ".log"
        logger = logging.getLogger(name)
        # formatter = logging.Formatter('%(asctime)s : %(message)s')
        formatter = logging.Formatter('%(message)s')
        fileHandler = logging.FileHandler(logFile, mode="a")
        fileHandler.setFormatter(formatter)

        logger.setLevel(logging.INFO)
        logger.addHandler(fileHandler)

    def info(self, message):
        logger.info(message)
