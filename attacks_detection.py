import time
import subprocess
from scapy.all import *
from get_net_info import get_ip_info
import threading

class network_attack_detector:

    def __init__(self):
        self.arp_table=self.get_arp_table()

        self.scanning=True

        self.real_ip_mac_pairs={}

        self.lock=threading.Lock()

        self.protocol_codes={6:'tcp',17:'udp',1:'icmp'}

        self.Dos_MAX_PACKETS = {
            "icmp": 500,
            "tcp": 600,
            "udp": 1000,
        }
        # Create a dictionary to store the number of packets from each IP address for each protocol
        self.Dos_packets = {
            "icmp": {},
            "tcp": {},
            "udp": {},
        }
        self.my_mac=Ether().src

        self.arp_packets={}

        self.brodcast_packets=[]
    
    def collect_ip_mac_pairs(self,pkt):
        if IP in pkt and Ether in pkt:
            self.real_ip_mac_pairs[pkt[Ether].src]=pkt[Ether].src

    def get_arp_table(self):
        my_ip=get_ip_info()[0]
        arp_entries = subprocess.check_output(["arp", "-a"]).decode("utf-8").strip()
        arp_entries=arp_entries[arp_entries.find(my_ip):].split('\n')[2:]
        arp_table={}
        for entry in arp_entries:
            ip, mac, *_ = map(str.strip,entry.split())
            arp_table[ip] = mac

        return arp_table

    def detect_arp_spoofing(self,pkt):
        if not self.scanning:
            quit()

        if pkt[Ether].src!=self.my_mac and ARP in pkt and pkt[ARP].op == 2:
            src_mac = pkt[ARP].hwsrc
            src_ip = pkt[ARP].psrc
            dst_mac = pkt[ARP].hwdst
            dst_ip = pkt[ARP].pdst

            if src_mac in self.real_ip_mac_pairs.keys():
                if self.real_ip_mac_pairs[src_mac]!=src_ip:
                    print(f"ARP spoofing detected from {src_mac} to {dst_mac} ({dst_ip})!")

            #check if a device on the network is sending too much arp responses to another device
            for pair in self.arp_packets.keys():
                for pkt_time in self.arp_packets[pair]:
                    if time.time()-pkt_time>60:
                        self.arp_packets[pair].remove(pkt_time)

            if (src_mac,dst_mac) in self.arp_packets.keys():
                self.arp_packets[(src_mac,dst_mac)].append(time.time())
            else:
                self.arp_packets[(src_mac,dst_mac)] = [time.time()]

            for pair,p_list in self.arp_packets.items():
                if len(p_list) >=30:
                    print(f"Possible Arp spoofing attack from {pair[0]} to {pair[1]} with {len(p_list)} packets in the last minute")

            # check for conflicting entries in ARP table
            if src_mac != self.arp_table.get(src_ip):
                print(f"Possible ARP spoofing detected from {src_mac} to {dst_mac} ({dst_ip})!")
            
    def detect_dos(self,pkt):
        if not self.scanning:
            quit()

        if IP in pkt and pkt.proto in self.protocol_codes.keys():
            for prot in self.Dos_packets.keys():
                for ip in self.Dos_packets[prot].keys():
                    for pkt_time in self.Dos_packets[prot][ip]:
                        if time.time()-pkt_time>1:
                            self.Dos_packets[prot][ip].remove(pkt_time)

            protocol = self.protocol_codes[pkt.proto]
            ip = pkt[IP].src

            if ip in self.Dos_packets[protocol]:
                self.Dos_packets[protocol][ip].append(time.time())
            else:
                self.Dos_packets[protocol][ip] = [time.time()]

            for protocol,limit in  self.Dos_MAX_PACKETS.items():
                for ip, p_list in self.Dos_packets[protocol].items():
                    if len(p_list) >=  limit:
                        print(f"Possible DoS attack from {ip} with {len(p_list)} {protocol} self.Dos_packets")

    def detect_broadcast_storms(self,pkt):
        if not self.scanning:
            quit()

        if Ether in pkt and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            for pkt_time in self.brodcast_packets:
                if time.time()-pkt_time>1:
                    self.brodcast_packets.remove(pkt_time)
            
            self.brodcast_packets.append(time.time())

            if len(self.brodcast_packets)>600:
                print(f'possible brodcast storm with {len(self.brodcast_packets)} pps')

    def start_sniffers(self):
        pair_thr=threading.Thread(target=sniff,kwargs={'prn':self.collect_ip_mac_pairs ,'store': False})
        arp_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_arp_spoofing ,'store': False})
        dos_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_dos ,'store': False})
        brodcast_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_broadcast_storms ,'store': False})

        threads=[pair_thr,arp_thr,dos_thr,brodcast_thr]

        for t in threads:
            t.start()

s=network_attack_detector()
s.start_sniffers()