# Importing necessary modules
from scapy.all import *
from get_net_info import *

class network_transmition_scanner():
    def __init__(self):
        self.total_bytes = 0  # total number of bytes transmitted
        self.devices ={}  # dictionary to keep track of devices and their transmitted bytes
        self.scanning=True  # flag to indicate whether scanning is still ongoing

    def run_scanner(self):
        # Start sniffing packets and call packet_callback function for each packet
        sniff(prn=self.packet_callback,store=False)
        
    def packet_callback(self,packet):
        # Check if scanning is still ongoing, exit if it is not
        if self.scanning==False:
            sys.exit()
        
        if packet.haslayer(IP):
            src = packet[IP].src  # source IP address
            dst = packet[IP].dst  # destination IP address
            size = packet[IP].len  # packet size in bytes
            
            # Increment total_bytes by the size of the packet
            self.total_bytes += size
            
            # Check if source IP is on the local network, update devices dictionary
            if self.is_in_lan(src):
                if src in self.devices.keys():
                    self.devices[src] += size
                else:
                    self.devices[src] = size
            
            # Check if destination IP is on the local network, update devices dictionary
            if self.is_in_lan(dst):
                if dst in self.devices.keys():
                    self.devices[dst] += size
                else:
                    self.devices[dst] = size

    def is_in_lan(self,ip):
        net_info=get_ip_info()
        my_ip=net_info[0].split('.')  # local IP address
        ip=ip.split('.')  # IP address to check
        subnet_mask=net_info[2].split('.')  # subnet mask
        
        ip=list(map(int,ip))
        my_ip=list(map(int,my_ip))
        subnet_mask=list(map(int,subnet_mask))

        on_lan=True
        for i in range(len(ip)):
            # Check if the ith octet of the IP address is in the local network
            if ip[i]&subnet_mask[i]!=my_ip[i]&subnet_mask[i]:
                on_lan=False
        
        return on_lan
