from scapy.all import ARP,Ether,srp1
import threading
from Hostname_resolver import Hostname_Resolver
from port_scanner import PortScanner
from Device import Device
from network_transmition_scanner import network_transmition_scanner
import re
import socket
import subprocess

class network_scanner():
  def __init__(self) :
    self.devices: list[Device]= []
    self.ips_to_scan=[]
    self.finished_scanning_count=0
    self.stop_flag=False
    self.lock=threading.Lock()
    self.name_resolver=Hostname_Resolver()
    mdsn_sniffer=threading.Thread(target=self.name_resolver.start_mdsn_sniffing)
    mdsn_sniffer.start()
    self.ps=PortScanner()
    self.net_transfer=network_transmition_scanner()
    net_transfer_thr=threading.Thread(target=self.net_transfer.run_scanner)
    net_transfer_thr.start()
    self.scanning=False
    self.is_ps_all=False
    self.is_resolving_names=False

  def scan_network(self):
    self.scanners=[]
    self.results={}
    self.scanning=True

    self.stop_flag=False

    for i in range(0,len(self.ips_to_scan),4):
      s=threading.Thread(target=self.arp_scanner, args=(self.ips_to_scan[i:i+4],))
      self.scanners.append(s)
    
    for s in self.scanners:
      s.start()

    for s in self.scanners:
      s.join()

    if not self.stop_flag:
      for device in self.devices:
        if device.ip in self.results.keys():
          device.is_alive=True
          self.results.__delitem__(device.ip)
        else:
          if not self.stop_flag and device.ip in self.ips_to_scan:
            if self.ping_verefication(device.ip):
              device.is_alive=False
      
      for ip,mac in self.results.items():
        d=Device(ip,mac,self.ps,self.name_resolver)
        self.devices.append(d)

    self.scanning=False
    
    self.finished_scanning_count=0
  
  def ping_verefication(self,ip):
    result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode != 0

  def resolve_all_names(self):
    name_threads=[]
    self.is_resolving_names=True
    for device in self.devices:
      thr=threading.Thread(target=self.name_resolver.resolve_ip,args=(device.ip,))
      name_threads.append(thr)
    
    for i in range(len(name_threads)):
        name_threads[i].start()
      
    for i in range(len(name_threads)):
        name_threads[i].join()

    for device in self.devices:
      if device.ip in self.name_resolver.devices.keys():
        device.name=self.name_resolver.devices[device.ip]

    self.is_resolving_names=False
    
  def port_scan_all_devices(self):
    ps_threads=[]
    self.is_ps_all=True
    for device in self.devices:
      thr=threading.Thread(target=self.ps.popular_scan,args=(device.ip,'detailed'))
      ps_threads.append(thr)
    
    for i in range(len(ps_threads)):
        ps_threads[i].start()
      
    for i in range(len(ps_threads)):
        ps_threads[i].join()

    self.stop_flag=False
    self.finished_scanning_count=0

    for device in self.devices:
        device.ports=self.ps.scanned[device.ip]
    self.is_ps_all=False

  def update_data_transfered(self):
    for device in self.devices:
      if device.ip in self.net_transfer.devices.keys():
        device.data_transfered=self.net_transfer.devices[device.ip]

  def arp_scanner(self,ip_list):
    p=Ether(dst='FF:FF:FF:FF:FF:FF')/ARP()
    for ip in ip_list:
        if self.stop_flag:
          return
        target_ip=ip
        p[ARP].pdst=target_ip
        response=srp1(p,timeout=2.5,verbose=0)
        if self.stop_flag:
          return
        if response:
          with self.lock:
            self.results[response[ARP].psrc]=response[ARP].hwsrc

        self.finished_scanning_count+=1

  def close_all_tools(self):
    self.name_resolver.scanning=False
    self.ps.scanning=False
    self.net_transfer.scanning=False
    self.ps.port_con.scanning=False

  def parse_ip_input(self,ip_input):
    if  re.search("[a-z]", ip_input) or re.search("[A-Z]", ip_input):
        return False
        
    try:
      ip_list = []
      
      ip_ranges = ip_input.split(',')

      for ip_range in ip_ranges:
          if '-' in ip_range:
              start_ip, end_num = ip_range.split('-')
              start_ip_parts = start_ip.split('.')
              for part in start_ip_parts:
                 if len(part)==0:
                    return False
              
              differnece=int(end_num)-int(start_ip_parts[-1])
              for i in range(len(start_ip_parts)):
                 while len(start_ip_parts[i])<3:
                    start_ip_parts[i]='0'+start_ip_parts[i]
              start_int = int(''.join(start_ip_parts))
              for i in range(start_int, start_int+differnece+1):
                  i=str(i)
                  ip_list.append(f"{i[:3].removeprefix('0').removeprefix('0')}.{i[3:6].removeprefix('0').removeprefix('0')}.{i[6:9].removeprefix('0').removeprefix('0')}.{i[9:12].removeprefix('0').removeprefix('0')}")
          else:
              ip_list.append(ip_range)
      
      if len(ip_list)==0:
         return False

      #check if all adresses are valid ip adresses, raises error if not
      for ip in ip_list:
        if ip.count(".")!=3:
           return False
        socket.inet_aton(ip)

      self.ips_to_scan=ip_list
      return True
    
    except:
       return False