import time
import datetime
import subprocess
from scapy.all import *
from get_net_info import get_ip_info
import threading
import pyshark
from pyshark.tshark.tshark import get_all_tshark_interfaces_names
import asyncio

class network_attack_detector:

    def __init__(self):
        self.attacks_records={'arp':[],'dos':[],'brodcast':[],'ps':[],'malware':[]}

        self.arp_table=self.get_arp_table()

        self.scanning=True

        self.real_ip_mac_pairs={}

        self.lock=threading.Lock()

        self.protocol_codes={6:'tcp',17:'udp',1:'icmp'}

        self.Dos_MAX_PACKETS = {
            "icmp": 1500,
            "tcp": 2500,
            "udp": 3000,
        }
        # Create a dictionary to store the number of packets from each IP address for each protocol
        self.Dos_packets = {
            "icmp": {},
            "tcp": {},
            "udp": {},
        }
        self.dos_attacks={}

        self.my_mac=Ether().src
        self.my_ip=get_ip_info()[0]

        self.arp_packets={}
        self.arp_attacks={}

        self.port_scan_packets={}
        self.port_scan_attacks={}

        self.brodcast_packets=[]
        self.brodcast_attack=-100
    
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
    
    def collect_ip_mac_pairs(self,pkt):
        if IP in pkt and Ether in pkt:
            if self.is_in_lan(pkt[IP].src):
                self.real_ip_mac_pairs[pkt[Ether].src]=pkt[IP].src

    def get_arp_table(self):
        my_ip=get_ip_info()[0]
        arp_entries = subprocess.check_output(["arp", "-a"]).decode("utf-8").strip()
        arp_entries=arp_entries[arp_entries.find(my_ip):].split('\n')[2:]
        arp_table={}
        for entry in arp_entries:
            ip, mac, *_ = map(str.strip,entry.split())
            arp_table[ip] = mac.replace('-',':')

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
                if self.real_ip_mac_pairs[src_mac]!=src_ip and not((pkt[Ether].src,pkt[Ether].dst) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]<10):
                    self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now()}")
                    self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]=time.time()
                    return

            #check if a device on the network is sending too much arp responses to another device
            for pair in self.arp_packets.keys():
                for pkt_time in self.arp_packets[pair]:
                    if time.time()-pkt_time>60:
                        self.arp_packets[pair].remove(pkt_time)

            if (src_mac,dst_mac) in self.arp_packets.keys():
                self.arp_packets[(pkt[Ether].src,pkt[Ether].dst)].append(time.time())
            else:
                self.arp_packets[(pkt[Ether].src,pkt[Ether].dst)] = [time.time()]

            for pair,p_list in self.arp_packets.items():
                if len(p_list) >=30 and not((pair[0],pair[1]) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pair[0],pair[1])]<10):
                    self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now()}")
                    self.arp_attacks[(pair[0],pair[1])]=time.time()
                    return

            # check for conflicting entries in ARP table
            if src_mac != self.arp_table.get(src_ip) and not((pkt[Ether].src,pkt[Ether].dst) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]<10):
                self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now()}")
                self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]=time.time()
                return
            
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
                    if len(p_list) >=  limit and not (ip in self.dos_attacks.keys() and time.time()-self.dos_attacks[ip]<10):
                        self.attacks_records['dos'].append(f"Possible DoS attack from {ip} with {len(p_list)} {protocol} at {datetime.now()}")
                        self.dos_attacks[ip]=time.time()

    def detect_broadcast_storms(self,pkt):
        if not self.scanning:
            quit()

        if Ether in pkt and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            for pkt_time in self.brodcast_packets:
                if time.time()-pkt_time>1:
                    self.brodcast_packets.remove(pkt_time)
            
            self.brodcast_packets.append(time.time())

            if len(self.brodcast_packets)>600 and time.time()-self.brodcast_attack>10:
                self.attacks_records['brodcast'].append(f'possible brodcast storm with {len(self.brodcast_packets)} pps at {datetime.now()}')
                self.brodcast_attack=time.time()

    #can show that someone is attempting to gather information about your network or exploit vulnerabilities 
    def detect_port_scanning(self,pkt):
        if IP in pkt:
            if (TCP in pkt and pkt[TCP].flags == 0x02) or UDP in pkt:
                src_ip=pkt[IP].src
                dst_ip=pkt[IP].dst
                protocol = self.protocol_codes[pkt.proto].upper()
                port=pkt[protocol].dport

                for pair in self.port_scan_packets.keys():
                    for pkt_time,prt in self.port_scan_packets[pair]:
                        if time.time()-pkt_time>120:
                            self.port_scan_packets[pair].remove((pkt_time,prt))
                
                if (src_ip,dst_ip) in self.port_scan_packets.keys():
                    exists=False
                    for i in range(len(self.port_scan_packets[(src_ip,dst_ip)])):
                        seen_port=self.port_scan_packets[(src_ip,dst_ip)][i][1]
                        if seen_port==port:
                            self.port_scan_packets[(src_ip,dst_ip)][i]=(time.time(),port)
                            exists=True

                    if not exists:
                        self.port_scan_packets[(src_ip,dst_ip)].append((time.time(),port))

                else:
                    self.port_scan_packets[(src_ip,dst_ip)] = [(time.time(),port)]

                for pair,p_list in self.port_scan_packets.items():
                    if len(p_list) >=30 and not ((pair[0],pair[1]) in self.dos_attacks.keys() and time.time()-self.dos_attacks[(pair[0],pair[1])]<10):
                        self.attacks_records['ps'].append(f"Possible Port scanning by {pair[0]} on {pair[1]} with {len(p_list)} ports scanned at {datetime.now()}")
                        self.dos_attacks[(pair[0],pair[1])]=time.time()

    def malware_sig_detection(self):
        for i,name in enumerate(get_all_tshark_interfaces_names()):
            if 'Wi-Fi' in name:
                interface = get_all_tshark_interfaces_names()[i-1]

        # Define a list of malware signatures to look for in the traffic
        signatures = [
            'ET MALWARE Possible AgentTesla CnC Beacon',
            'ET MALWARE Trickbot CnC Beacon',
            'ET MALWARE Emotet CnC Beacon',
            'ET MALWARE Lokibot CnC Beacon',
            'ET MALWARE ZLoader CnC Beacon',
            'ET MALWARE Ursnif CnC Beacon',
            'ET MALWARE Dridex CnC Beacon',
            'ET MALWARE Qakbot CnC Beacon',
            'ET MALWARE SmokeLoader CnC Beacon',
            'ET MALWARE Ramnit CnC Beacon',
            'ET MALWARE Nanocore CnC Beacon',
            'ET MALWARE Formbook CnC Beacon',
            'ET MALWARE Pony CnC Beacon',
            'ET TROJAN APT32 Downloader',
            'ET TROJAN APT32 CnC Beacon',
            'ET TROJAN APT37 CnC Beacon',
            'ET TROJAN APT39 CnC Beacon',
            'ET TROJAN APT41 CnC Beacon',
            'ET TROJAN Dridex CnC Beacon',
            'ET TROJAN Emotet CnC Beacon',
            'ET TROJAN Gootkit CnC Beacon',
            'ET TROJAN IcedID CnC Beacon',
            'ET TROJAN Metasploit Meterpreter Payload Detected',
            'ET TROJAN Mirai Variant User-Agent Detected (Linux)',
            'ET TROJAN Mirai Variant User-Agent Detected (Windows)',
            'ET TROJAN Nanocore CnC Beacon',
            'ET TROJAN Necurs CnC Beacon',
            'ET TROJAN NetWire CnC Beacon',
            'ET TROJAN njRAT CnC Beacon',
            'ET TROJAN Pony CnC Beacon',
            'ET TROJAN Qakbot CnC Beacon',
            'ET TROJAN Quasar RAT CnC Beacon',
            'ET TROJAN Remcos RAT CnC Beacon',
            'ET TROJAN SmokeLoader CnC Beacon',
            'ET TROJAN Trickbot CnC Beacon',
            'ET TROJAN Ursnif CnC Beacon',
            'ET TROJAN Vawtrak CnC Beacon',
            'ET TROJAN WastedLocker Ransomware CnC Beacon',
            'ET TROJAN Winnti Variant CnC Beacon',
            'ET TROJAN ZLoader CnC Beacon',
            'ET EXPLOIT Possible MS17-010 SMB RCE Attempt',
            'ET EXPLOIT Possible EternalBlue Exploit M2',
            'ET EXPLOIT Possible BlueKeep MSRC 2019-0708 RDP Remote Windows Kernel Use After Free',
            'ET EXPLOIT Possible BlueKeep Related RDP DoS Attempt'
        ]

        # Create a packet capture object using PyShark
        filter_expr = ' or '.join([f'http contains "{sig}"' for sig in signatures])
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = pyshark.LiveCapture(interface=interface,capture_filter=filter_expr,display_filter=filter_expr)

        # Define a filter to only capture traffic that matches the malware signatures
        while True:
            capture.sniff(1)
            try:
                #only if a packet was added to the packet list
                capture.next_packet()
                self.attacks_records['malware'].append(f'possible malware detected in a packet with http protocol at {datetime.now()}')
            except:
                pass
        
    def start_sniffers(self):
        pair_thr=threading.Thread(target=sniff,kwargs={'prn':self.collect_ip_mac_pairs ,'store': False})
        arp_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_arp_spoofing ,'store': False})
        dos_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_dos ,'store': False})
        brodcast_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_broadcast_storms ,'store': False})
        port_scanning_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_port_scanning ,'store': False})
        malware_detection_thr=threading.Thread(target=self.malware_sig_detection)

        threads=[pair_thr,arp_thr,dos_thr,brodcast_thr,port_scanning_thr,malware_detection_thr]

        for t in threads:
            t.start()
        
        while True:
            print(self.attacks_records['ps'])
            time.sleep(10)

s=network_attack_detector()
s.start_sniffers()