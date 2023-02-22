from scapy.all import ARP,Ether,srp1
import get_net_info
import threading
from Hostname_resolver import Hostname_Resolver
from port_scanner import PortScanner
from Device import Device
from network_transmition_scanner import network_transmition_scanner

class network_scanner():
  def __init__(self) :
    self.devices: list[Device]= []
    self.ips_to_scan=get_net_info.get_ip_info()[3]
    self.lock=threading.Lock()
    self.name_resolver=Hostname_Resolver()
    mdsn_sniffer=threading.Thread(target=self.name_resolver.start_mdsn_sniffing)
    mdsn_sniffer.start()
    self.ps=PortScanner()
    self.net_transfer=network_transmition_scanner()
    net_transfer_thr=threading.Thread(target=self.net_transfer.run_scanner)
    net_transfer_thr.start()

  def scan_network(self):
    self.scanners=[]
    self.results={}

    for i in range(0,len(self.ips_to_scan),4):
      s=threading.Thread(target=self.arp_scanner, args=(self.ips_to_scan[i:i+4],))
      self.scanners.append(s)
    
    for s in self.scanners:
      s.start()

    for s in self.scanners:
      s.join()
    
    for device in self.devices:
      if device.ip in self.results.keys():
        self.results.__delitem__(device.ip)
      else:
        device.is_alive=False
    
    for ip,mac in self.results.items():
      d=Device(ip,mac,self.ps,self.name_resolver)
      self.devices.append(d)
  
  def resolve_names(self):
    name_threads=[]
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
    
  def port_scan_devices(self):
    ps_threads=[]
    for device in self.devices:
      thr=threading.Thread(target=self.ps.popular_scan,args=(device.ip,'detailed'))
      ps_threads.append(thr)
    
    for i in range(len(ps_threads)):
        ps_threads[i].start()
      
    for i in range(len(ps_threads)):
        ps_threads[i].join()

    for device in self.devices:
        device.ports=self.ps.scanned[device.ip]

  def update_data_transfered(self):
    for device in self.devices:
      if device.ip in self.net_transfer.devices.keys():
        device.data_transfered=self.net_transfer.devices[device.ip]

  def arp_scanner(self,ip_list):
    p=Ether(dst='FF:FF:FF:FF:FF:FF')/ARP()
    for ip in ip_list:
        target_ip=ip
        p[ARP].pdst=target_ip
        response=srp1(p,timeout=3,verbose=0)
        if response:
          with self.lock:
            self.results[response[ARP].psrc]=response[ARP].hwsrc

  def close_all_tools(self):
    self.name_resolver.scanning=False
    self.ps.scanning=False
    self.net_transfer.scanning=False
    self.ps.port_con.scanning=False

n=network_scanner()
n.scan_network()
n.resolve_names()
n.port_scan_devices()
n.update_data_transfered()

for device in n.devices:
  print(device)
  print('=========================================================================')

n.close_all_tools()