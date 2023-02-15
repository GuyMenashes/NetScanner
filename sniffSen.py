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
        quitter=threading.Thread(target=exit)
        quitter.start()
        sender=threading.Thread(target=self.send_pcap)
        sender.start()
        sender.join()
        snif.join()
        quitter.join()
        
    def send_pcap(self):
        while True:
            while(self.server.recieve()==None):
                pass

            wrpcap('sent_pcap.pcap',self.sniffed_packets)

            with open('sent_pcap.pcap','rb') as f:
                pcbytes=f.read()
            
            length=f'{len(pcbytes)}'
            self.server.send(length)
            start=0
            end=4096
            while end<len(pcbytes):
                pcbytes_part=pcbytes[start:end]
                self.server.send(pcbytes_part,isBytes=True)
                start=end
                end+=4096
            self.server.send(pcbytes[start:],isBytes=True)   
            print('The pcap file was sent')   

    def sniffer(self):
        sniff(prn=self.save_packet)

    def save_packet(self,p):
        with self.lock:
            self.sniffed_packets.append(p)
        if not self.scanning:
            wrpcap('sent_pcap.pcap',self.sniffed_packets)
            quit()

SniffSen()