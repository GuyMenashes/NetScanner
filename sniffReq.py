from socket import *
from encrypted_client import *

class SniffReq:
    def __init__(self,ip):
        self.client=encrypted_client(ip,45689)
        self.client.run_server()

    def request_pcap(self):
        try:
            length=int(self.client.recieve())
        except:
            return
        
        if length<=1024:
            res=self.client.recieve(isBytes=True)

        else:
            res=b''
            while(length>0):
                res_part=self.client.recieve(5560,True)
                res+=res_part
                length-=4096
        with open('recieved_pcap.pcap','wb') as f:
            f.write(res)