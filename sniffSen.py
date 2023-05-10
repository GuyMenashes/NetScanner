import threading
from scapy.all import *
from encrypted_server import *
from scapy.all import *


class SniffSen:
    def __init__(self):
        self.sniffed_packets=[]
        self.scanning=True
        self.lock=threading.Lock()
        threading.Thread(target=self.sniffer).start()

        with open('sent_pcap.pcap','wb') as f:
            f.write(b'')

    def send_pcap(self):
        self.server=encrypted_server(45689)
        self.server.start_server()

        length=os.path.getsize('sent_pcap.pcap')

        self.server.send(str(length))

        with self.lock:
            with open('sent_pcap.pcap','rb') as f:
                pcbytes=f.read()

        self.server.recieve()

        if length>600_000:
            for i in range(0,length,500000):
                if i+500000<length:
                    self.server.send(pcbytes[i:i+500000],isBytes=True)
                    self.server.recieve()
                else:
                    self.server.send(pcbytes[i:],isBytes=True)
                    self.server.recieve()
        else:
            self.server.send(pcbytes,isBytes=True)
            self.server.recieve()

        try:
            self.server.server_socket.close()
            self.server.client.close()
        finally:
            del self.server
        
    def sniffer(self):
        sniff(prn=self.save_packet)

    def save_packet(self,p):
        with self.lock:
            wrpcap('sent_pcap.pcap', p, append=True)
            if os.path.getsize('sent_pcap.pcap')>2_500_000:
                with open('sent_pcap.pcap','wb'):
                    pass
        if not self.scanning:
            quit()