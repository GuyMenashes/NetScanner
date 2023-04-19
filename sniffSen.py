import threading
from scapy.all import *
from encrypted_server import *

class SniffSen:
    def __init__(self):
        self.server=encrypted_server(45689)
        self.server.start_server()

        self.sniffed_packets=[]
        self.scanning=True
        self.lock=threading.Lock()
        snif=threading.Thread(target=self.sniffer)
        snif.start()
        listener=threading.Thread(target=self.request_listener)
        listener.start()
        sender=threading.Thread(target=self.send_pcap)
        sender.start()
        sender.join()
        snif.join()
        
    def send_pcap(self):
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
    
    def request_listener(self):
        while self.scanning:
            try:
                recieved=self.server.recieve()
            except:
                del self.server
                time.sleep(0.2)
                self.server=encrypted_server(45689)
                self.server.start_server()
            if recieved:
                self.send_pcap()
        
    def sniffer(self):
        sniff(prn=self.save_packet)

    def save_packet(self,p):
        with self.lock:
            self.sniffed_packets.append(p)
        if not self.scanning:
            wrpcap('sent_pcap.pcap',self.sniffed_packets)
            quit()

SniffSen()