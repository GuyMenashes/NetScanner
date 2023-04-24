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

    def send_pcap(self):
        self.server=encrypted_server(45689)
        self.server.start_server()
        
        wrpcap('sent_pcap.pcap',self.sniffed_packets)

        with open('sent_pcap.pcap','rb') as f:
            pcbytes=f.read()
        
        length=f'{len(pcbytes)}'
        
        try:
            self.server.send(length)
        except:
            self.scanning=False
            return
        start=0
        end=4096
        while end<len(pcbytes):
            pcbytes_part=pcbytes[start:end]
            try:
                self.server.send(pcbytes_part,isBytes=True)
            except:
                self.scanning=False
                return
                
            start=end
            end+=4096
        try:
            self.server.send(pcbytes[start:],isBytes=True) 
        except:
            self.scanning=False
            return  
        
        try:
            self.server.server_socket.close()
            self.server.client.close()
        finally:
            del self.server
        
    def sniffer(self):
        sniff(prn=self.save_packet)

    def save_packet(self,p):
        with self.lock:
            self.sniffed_packets.append(p)
        if not self.scanning:
            wrpcap('sent_pcap.pcap',self.sniffed_packets)
            sys.exit()