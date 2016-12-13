'''
Created on 02.12.2016

@author: manuel
'''

import logging, logging.handlers


logger = logging.getLogger("oschameleon")

class Log(object):
    def __init__(self, name):
        self.setup(name)
    
    def setup(self, name):
        #self.remote_logging(name, server)
        self.py_logging(name)
        
    def remote_logging(self, name, server):
        rootLogger = logging.getLogger('')
        rootLogger.setLevel(logging.DEBUG)
        print server
        socketHandler = logging.handlers.SocketHandler(server,
                            logging.handlers.DEFAULT_TCP_LOGGING_PORT)
        # don't bother with a formatter, since a socket handler sends the event as
        # an unformatted pickle
        rootLogger.addHandler(socketHandler)

        
    def py_logging(self, name):
        print ("log", name)
        path = "/var/log/honeypot/" + name + ".log"
        logger = logging.getLogger(name)
        formatter = logging.Formatter('%(asctime)s : %(message)s')
        fileHandler = logging.FileHandler(path, mode="a")
        fileHandler.setFormatter(formatter)

        logger.setLevel(logging.INFO)
        logger.addHandler(fileHandler)

    def info(self, message):
        logger.info(message)
