import time
import configparser

from snap7.server import Server
from snap7.server import logger
from snap7 import types
import logging


MEMORY_AREA_SIZE = 'MemoryAreaSize'
PORT = 'Port'
LOGGING = 'Logging'
SERVER = 'SERVER'

DEFAULT_CONFIG_FILE = 'main.ini'

TRUE_KEYWORD = 'True'


class S7CommServer(Server):
        def __init__(self,config):

            self.size = int(config[MEMORY_AREA_SIZE])
            self.port = int(config[PORT])
            self.isWorking = True

            logging.basicConfig(level=logging.INFO)

            Server.__init__(self,config[LOGGING] == TRUE_KEYWORD)

            self.initializeMemory()

        def initializeMemory(self):
            DBdata = (types.wordlen_to_ctypes[types.S7WLByte] * self.size)()
            PAdata = (types.wordlen_to_ctypes[types.S7WLByte] * self.size)()
            TMdata = (types.wordlen_to_ctypes[types.S7WLByte] * self.size)()
            CTdata = (types.wordlen_to_ctypes[types.S7WLByte] * self.size)()

            Server.register_area(self,types.srvAreaDB, 1, DBdata)
            Server.register_area(self,types.srvAreaPA, 1, PAdata)
            Server.register_area(self,types.srvAreaTM, 1, TMdata)
            Server.register_area(self,types.srvAreaCT, 1, CTdata)

        def start(self):

            Server.start(self,tcpport=self.port)

            while self.isWorking:
                event = Server.pick_event(self)
                if event:
                    logger.info(Server.event_text(self,event))

        def stop(self):
            self.isWorking = False
            Server.destroy(self)


if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read(DEFAULT_CONFIG_FILE)
    server = S7CommServer(config[SERVER])

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
