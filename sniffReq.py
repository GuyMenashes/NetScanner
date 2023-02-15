from socket import *
import time
from encrypted_client import *

class SniffReq:
    def __init__(self):
        self.client=encrypted_client('127.0.0.1',45689)
        self.client.start_server()

        self.recieve_pcap()

    def recieve_pcap(self):
        time.sleep(10)
        self.client.Send('h')
        length=int(self.recieve())
        print(length)
        if length<=1024:
            res=self.client.recieve()
            print(res)
        else:
            res=b''
            while(length>0):
                res_part=self.client.recieve(5560,True)
                res+=res_part
                length-=4096
                print(length)
            with open('recieved_pcap.pcap','wb') as f:
                f.write(res)

SniffReq()