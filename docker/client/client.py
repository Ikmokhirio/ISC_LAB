import time
import configparser

from snap7.client import Client
from snap7 import types
import socket


MEMORY_AREA_SIZE = 'MemoryAreaSize'
PORT = 'Port'
IP_ADDRESS = 'IpAddress'
CLIENT = 'CLIENT'

DEFAULT_CONFIG_FILE = 'main.ini'

TRUE_KEYWORD = 'True'


class S7CommClient(Client):
        def __init__(self,config):

            try:
                self.ip=socket.gethostbyname(config[IP_ADDRESS])
            except:
                self.ip = config[IP_ADDRESS]

            print("Connectiont to",self.ip)
            self.port = int(config[PORT])
            self.isWorking = True

            Client.__init__(self)


        def start(self):

            Client.connect(self,self.ip,0,0,self.port)
            while(True):
                Client.db_read(self,1, 0, 4)
                time.sleep(3)


        def stop(self):
            Client.disconnect(self)
            self.isWorking = False


if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read(DEFAULT_CONFIG_FILE)
    client = S7CommClient(config[CLIENT])

    try:
        client.start()
    except KeyboardInterrupt:
        client.stop()
