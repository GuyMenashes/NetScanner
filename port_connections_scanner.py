from scapy.all import *
from get_net_info import *

class port_connections_scanner():

    def __init__(self):
        self.connections={}
        self.scanning=True
        self.my_ip=get_ip_info()[0]

    def run_scanner(self):
        # Start sniffing packets
        sniff(lfilter=self.packet_filter, prn=self.packet_handler)

    # Define a function to handle incoming packets
    def packet_handler(self,packet):
        if not self.scanning:
            quit()
            
        if self.is_in_lan(packet[IP].dst):
            if self.connections.get((packet[IP].dst,packet[TCP].dport)):
                if (packet[IP].src,packet[TCP].sport) not in self.connections[(packet[IP].dst,packet[TCP].dport)]:
                    self.connections[(packet[IP].dst,packet[TCP].dport)].append((packet[IP].src,packet[TCP].sport))
            else:
                self.connections[(packet[IP].dst,packet[TCP].dport)]=[(packet[IP].src,packet[TCP].sport)]
        if self.is_in_lan(packet[IP].src):
            if self.connections.get((packet[IP].src,packet[TCP].sport)):
                if (packet[IP].dst,packet[TCP].dport) not in self.connections[(packet[IP].src,packet[TCP].sport)]:
                    self.connections[(packet[IP].src,packet[TCP].sport)].append((packet[IP].dst,packet[TCP].dport))
            else:
                self.connections[(packet[IP].src,packet[TCP].sport)]=[(packet[IP].dst,packet[TCP].dport)]

    def packet_filter(self,packet):
        if not self.scanning:
            quit()
        if packet.haslayer(IP):
            if packet.haslayer(TCP) and (self.is_in_lan(packet[IP].dst) or self.is_in_lan(packet[IP].src)):
                if not (packet[IP].dst==self.my_ip or packet[IP].src==self.my_ip):
                    return True

    def is_in_lan(self,ip):
        net_info=get_ip_info()
        my_ip=self.my_ip.split('.')
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
    
    def get_connected_device(self,ip,port)-> list[tuple[str,int]]|None:
        value=self.connections.get((ip,port))
        if value:
            return value
        
        return None