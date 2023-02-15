from scapy.all import *
from get_net_info import *

class network_transmition_scanner():
    def __init__(self):
        self.total_bytes = 0
        self.devices ={}
        self.scanning=True

    def run_scanner(self):
        sniff(prn=self.packet_callback,store=False)
        
    def packet_callback(self,packet):
        if self.scanning==False:
            quit()
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            size = packet[IP].len
            self.total_bytes += size
            if self.is_in_lan(src):
                if src in self.devices.keys():
                    self.devices[src] += size
                else:
                    self.devices[src] = size
            if self.is_in_lan(dst):
                if dst in self.devices.keys():
                    self.devices[dst] += size
                else:
                    self.devices[dst] = size

    def is_in_lan(self,ip):
        net_info=get_ip_info()
        my_ip=net_info[0].split('.')
        ip=ip.split('.')
        subnet_mask=net_info[2].split('.')

        ip=list(map(int,ip))
        my_ip=list(map(int,my_ip))
        subnet_mask=list(map(int,subnet_mask))

        on_lan=True
        for i in range(len(ip)):
            if ip[i]&subnet_mask[i]!=my_ip[i]&subnet_mask[i]:
                on_lan=False
        
        return on_lan