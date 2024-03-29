# Import necessary modules
import time
import datetime
import subprocess
from scapy.all import *
from get_net_info import get_ip_info
import threading
import pyshark
from pyshark.tshark.tshark import get_all_tshark_interfaces_names
import asyncio

# Create class network_attack_detector
class network_attack_detector:

    # Initialize class variables and dictionaries
    def __init__(self):
        #Define a dictionary with a list of attacks for each attack type
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

        # Get IP and MAC addresses for current machine
        self.my_mac=Ether().src
        self.my_ip=get_ip_info()[0]

        self.arp_packets={}
        self.arp_attacks={}

        self.port_scan_packets={}
        self.port_scan_attacks={}

        self.brodcast_packets=[]
        self.brodcast_attack=-100

    # Function to determine if an IP address is on the local area network
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
    
    # Function to collect pairs of IP and MAC addresses
    def collect_ip_mac_pairs(self,pkt):
        if not self.scanning:
            sys.exit()
            
        if IP in pkt and Ether in pkt:
            if self.is_in_lan(pkt[IP].src):
                self.real_ip_mac_pairs[pkt[Ether].src]=pkt[IP].src

    # Function to get ARP table for current machine
    def get_arp_table(self):
        my_ip=get_ip_info()[0]
        arp_entries = subprocess.check_output(["arp", "-a"]).decode("utf-8").strip()
        arp_entries=arp_entries[arp_entries.find(my_ip):].split('\n')[2:]
        arp_table={}
        for entry in arp_entries:
            ip, mac, *_ = map(str.strip,entry.split())
            arp_table[ip] = mac.replace('-',':')

        return arp_table

    # This function is used to detect ARP spoofing attacks
    def detect_arp_spoofing(self,pkt):
        # check if the scanning flag is False. If so, terminate the program
        if not self.scanning:
            sys.exit()
            
        # check if the source MAC address of the packet is not the same as the MAC address of the system, 
        # and if it is an ARP packet with opcode 2 (which is a reply)
        if pkt[Ether].src!=self.my_mac and ARP in pkt and pkt[ARP].op == 2:
            # extract the relevant fields from the ARP packet
            src_mac = pkt[ARP].hwsrc
            src_ip = pkt[ARP].psrc
            dst_mac = pkt[ARP].hwdst
            dst_ip = pkt[ARP].pdst
            
            # check if the source MAC address is in the dictionary of real IP-MAC address pairs
            if src_mac in self.real_ip_mac_pairs.keys():
                # if the IP address for the given MAC address doesn't match the expected IP address, 
                # and if this is not a repeated attack within the last 10 seconds, record the attack 
                # and add it to the dictionary of ARP attacks
                if self.real_ip_mac_pairs[src_mac]!=src_ip and not((pkt[Ether].src,pkt[Ether].dst) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]<10):
                    self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]=time.time()
                    return
            
            # check if a device on the network is sending too many ARP responses to another device
            for pair in self.arp_packets.keys():
                for pkt_time in self.arp_packets[pair]:
                    if time.time()-pkt_time>60:
                        self.arp_packets[pair].remove(pkt_time)
            
            # add the current packet time to the list of ARP packets for the given source-destination MAC addresses
            if (src_mac,dst_mac) in self.arp_packets.keys():
                self.arp_packets[(pkt[Ether].src,pkt[Ether].dst)].append(time.time())
            else:
                self.arp_packets[(pkt[Ether].src,pkt[Ether].dst)] = [time.time()]
            
            # check if a device is sending too many ARP packets to another device, 
            # and if this is not a repeated attack within the last 10 seconds, record the attack 
            # and add it to the dictionary of ARP attacks
            for pair,p_list in self.arp_packets.items():
                if len(p_list) >=30 and not((pair[0],pair[1]) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pair[0],pair[1])]<10):
                    self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    self.arp_attacks[(pair[0],pair[1])]=time.time()
                    return

            # Check if there is a conflicting entry in the ARP table for the source IP and if this is not a repeated attack within the last 10 seconds
            if self.arp_table.get(src_ip) and src_mac != self.arp_table.get(src_ip) and not((pkt[Ether].src,pkt[Ether].dst) in self.arp_attacks.keys() and time.time()-self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]<10):
                
                # If there is a conflict, add an attack record with the detected MAC addresses and current time
                self.attacks_records['arp'].append(f"Possible ARP spoofing detected from {pkt[Ether].src} to {pkt[Ether].dst} at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                
                # Add the detected MAC addresses to the ARP attacks dictionary with the current time
                self.arp_attacks[(pkt[Ether].src,pkt[Ether].dst)]=time.time()
                
                # Return from the function to prevent further processing of the packet
                return

    # This function detects Denial of Service (DoS) attacks by monitoring the number of packets sent by each IP address for each protocol
    def detect_dos(self,pkt):
        # Exit if the system is not in scanning mode
        if not self.scanning:
            sys.exit()

        # Check if the packet is an IP packet with a protocol code in the protocol codes dictionary
        if IP in pkt and pkt.proto in self.protocol_codes.keys():
            # Remove old packets from the DoS packets dictionary
            for prot in self.Dos_packets.keys():
                for ip in self.Dos_packets[prot].keys():
                    for pkt_time in self.Dos_packets[prot][ip]:
                        if time.time()-pkt_time>1:
                            self.Dos_packets[prot][ip].remove(pkt_time)

            # Get the protocol and source IP address of the packet
            protocol = self.protocol_codes[pkt.proto]
            ip = pkt[IP].src

            # Add the packet's timestamp to the DoS packets dictionary for the given protocol and IP address
            if ip in self.Dos_packets[protocol]:
                self.Dos_packets[protocol][ip].append(time.time())
            else:
                self.Dos_packets[protocol][ip] = [time.time()]

            # Check if the number of packets from a given IP address for a given protocol exceeds the limit, and add an attack record if so
            for protocol,limit in  self.Dos_MAX_PACKETS.items():
                for ip, p_list in self.Dos_packets[protocol].items():
                    if len(p_list) >=  limit and not (ip in self.dos_attacks.keys() and time.time()-self.dos_attacks[ip]<10):
                        self.attacks_records['dos'].append(f"Possible DoS attack detected from {ip} with {len(p_list)} {protocol} at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                        self.dos_attacks[ip]=time.time()

    # This function detects broadcast storms by monitoring the number of broadcast packets received in a given time window
    def detect_broadcast_storms(self,pkt):
        # Exit if the system is not in scanning mode
        if not self.scanning:
            sys.exit()

        # Check if the packet is an Ethernet broadcast packet
        if Ether in pkt and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            # Remove old packets from the broadcast packets list
            for pkt_time in self.brodcast_packets:
                if time.time()-pkt_time>1:
                    self.brodcast_packets.remove(pkt_time)
            
            # Add the packet's timestamp to the broadcast packets list
            self.brodcast_packets.append(time.time())

            # Check if the number of broadcast packets exceeds the limit, and add an attack record if so
            if len(self.brodcast_packets)>600 and time.time()-self.brodcast_attack>10:
                self.attacks_records['brodcast'].append(f'possible brodcast storm detected with {len(self.brodcast_packets)} pps at {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}')
                self.brodcast_attack=time.time()

    # This function detects port scanning by analyzing packets and tracking the number of ports being scanned by each IP address
    def detect_port_scanning(self,pkt):
        # If scanning is not enabled, exit the function
        if not self.scanning:
            sys.exit()
        # If the packet is an IP packet
        if IP in pkt:
            # If the packet is a TCP packet with SYN flag or a UDP packet
            if (TCP in pkt and pkt[TCP].flags == 0x02) or UDP in pkt:
                # Extract source and destination IP addresses, protocol and destination port from the packet
                src_ip=pkt[IP].src
                dst_ip=pkt[IP].dst
                protocol = self.protocol_codes[pkt.proto].upper()
                port=pkt[protocol].dport

                # Remove packets from the dictionary that have been there for more than 10 seconds
                for pair in self.port_scan_packets.keys():
                    for pkt_time,prt in self.port_scan_packets[pair]:
                        if time.time()-pkt_time>10:
                            self.port_scan_packets[pair].remove((pkt_time,prt))

                # Check if the current packet is part of an existing scanning attempt
                if (src_ip,dst_ip) in self.port_scan_packets.keys():
                    exists=False
                    for i in range(len(self.port_scan_packets[(src_ip,dst_ip)])):
                        seen_port=self.port_scan_packets[(src_ip,dst_ip)][i][1]
                        if seen_port==port:
                            self.port_scan_packets[(src_ip,dst_ip)][i]=(time.time(),port)
                            exists=True

                    # If the packet is not part of an existing attempt, add it to the dictionary
                    if not exists:
                        self.port_scan_packets[(src_ip,dst_ip)].append((time.time(),port))
                # If the packet is not part of an existing attempt, create a new entry in the dictionary
                else:
                    self.port_scan_packets[(src_ip,dst_ip)] = [(time.time(),port)]

                # Check if the number of ports being scanned exceeds 30 and if it is not part of an existing DoS attack
                for pair,p_list in self.port_scan_packets.items():
                    if len(p_list) >=30 and not ((pair[0],pair[1]) in self.port_scan_attacks.keys() and time.time()-self.port_scan_attacks[(pair[0],pair[1])]<10):
                        # If the conditions are met, add a record to the attack_records dictionary
                        self.attacks_records['ps'].append(f"Possible Port scanning detected by {pair[0]} on {pair[1]} with {len(p_list)} ports scanned at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                        # Add the pair of IP addresses to the dictionary of DoS attacks
                        self.port_scan_attacks[(pair[0],pair[1])]=time.time()

    # Define a method to detect malware signatures in traffic
    def malware_sig_detection(self):
        # Loop through all available network interfaces and find the Wi-Fi interface
        for i,name in enumerate(get_all_tshark_interfaces_names()):
            if 'Wi-Fi' in name:
                interface = get_all_tshark_interfaces_names()[i-1]

        # Define a list of malware signatures to look for in the traffic
        signatures =  [
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

        # Create a packet capture object using PyShark and filter only traffic that matches malware signatures
        filter_expr = ' or '.join([f'http contains "{sig}"' for sig in signatures])
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        capture = pyshark.LiveCapture(interface=interface,capture_filter=filter_expr,display_filter=filter_expr)

        # Continuously sniff packets and log any matches with the malware signatures
        while True:
            # Exit the loop and close the capture object if the scanning flag is set to false
            if not self.scanning:
                capture.close()
                loop.close()
                sys.exit()

            # Sniff a single packet with a timeout of 0.5 seconds
            capture.sniff(1,timeout=0.5)

            try:
                # Get the next packet in the capture buffer
                capture.next_packet()

                # Log the detection of possible malware in the packet
                self.attacks_records['malware'].append(f'Possible malware detected in a packet with http protocol at {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}')
            except:
                # Continue sniffing if no packets are available
                pass

    # Define a method to start all packet sniffing threads
    def start_sniffers(self):
        # Create threads for each type of packet sniffing task
        pair_thr=threading.Thread(target=sniff,kwargs={'prn':self.collect_ip_mac_pairs ,'store': False})
        arp_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_arp_spoofing ,'store': False})
        dos_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_dos ,'store': False})
        brodcast_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_broadcast_storms ,'store': False})
        port_scanning_thr=threading.Thread(target=sniff,kwargs={'prn':self.detect_port_scanning ,'store': False})

        # Add all the threads to a list and start them
        threads=[pair_thr,arp_thr,dos_thr,brodcast_thr,port_scanning_thr]
        for t in threads:
            t.start()