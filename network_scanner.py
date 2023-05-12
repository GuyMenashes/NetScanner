# Importing necessary modules
from scapy.all import ARP,Ether,srp1
import threading
from Hostname_resolver import Hostname_Resolver
from port_scanner import PortScanner
from Device import Device
from network_transmition_scanner import network_transmition_scanner
import re
import socket
import subprocess
import get_net_info

class network_scanner():
  
  def __init__(self) :
    # Initialize class properties
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
    self.my_ip,self.default_gateway=get_net_info.get_ip_info()[:2]
    self.scanning=False
    self.is_ps_all=False
    self.is_resolving_names=False

  def scan_network(self):
    # Initialize properties and start scanning the network
    self.scanners=[]
    self.results={}
    self.scanning=True
    self.stop_flag=False

    # Divide the list of IP addresses into groups of four and spawn a thread for each group
    for i in range(0,len(self.ips_to_scan),4):
      s=threading.Thread(target=self.arp_scanner, args=(self.ips_to_scan[i:i+4],))
      self.scanners.append(s)
    
    # Start all of the threads
    for s in self.scanners:
      s.start()

    # Wait for all threads to finish
    for s in self.scanners:
      s.join()

    # If scanning has not been stopped, mark devices as alive or dead
    if not self.stop_flag:
      for device in self.devices:
        if device.ip in self.results.keys():
          device.is_alive=True
          self.results.__delitem__(device.ip)
        else:
          if not self.stop_flag and device.ip in self.ips_to_scan:
            if self.ping_verefication(device.ip):
              device.is_alive=False
      
      # Add any new devices that were found
      for ip,mac in self.results.items():
        d=Device(ip,mac,self.ps,self.name_resolver)
        self.devices.append(d)

    # Clean up after the scan is complete
    self.scanning=False
    self.finished_scanning_count=0
  
  def ping_verefication(self,ip):
    # Use the ping command to check if an IP is reachable
    result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = output.stdout.decode(encoding='utf-8',errors='ignore')
    return result.returncode != 0 or self.my_ip+':' in output

  def resolve_all_names(self):
      name_threads=[]  # create empty list to store threads
      self.is_resolving_names=True  # set flag to indicate name resolving process has started
      for device in self.devices:  # loop through all devices
        thr=threading.Thread(target=self.name_resolver.resolve_ip,args=(device.ip,))  # create a new thread for each device and add to the list
        name_threads.append(thr)
      
      for i in range(len(name_threads)):  # loop through the list of threads
          name_threads[i].start()  # start each thread
        
      for i in range(len(name_threads)):  # loop through the list of threads again
          name_threads[i].join()  # wait for each thread to finish

      for device in self.devices:  # loop through all devices again
        if device.ip in self.name_resolver.devices.keys():  # if the device's IP address is in the name resolver's devices dictionary
          device.name=self.name_resolver.devices[device.ip]  # set the device's name to the corresponding name in the dictionary

      self.is_resolving_names=False  # set flag to indicate name resolving process has finished
      
  def port_scan_all_devices(self):
      ps_threads=[]  # create empty list to store threads
      self.is_ps_all=True  # set flag to indicate port scanning process has started
      for device in self.devices:  # loop through all devices
        thr=threading.Thread(target=self.ps.popular_scan,args=(device.ip,'detailed'))  # create a new thread for each device and add to the list
        ps_threads.append(thr)
      
      for i in range(len(ps_threads)):  # loop through the list of threads
          ps_threads[i].start()  # start each thread
        
      for i in range(len(ps_threads)):  # loop through the list of threads again
          ps_threads[i].join()  # wait for each thread to finish

      self.stop_flag=False  # reset the stop flag
      self.finished_scanning_count=0  # reset the finished scanning count

      for device in self.devices:  # loop through all devices again
          device.ports=self.ps.scanned[device.ip]  # set the device's ports to the corresponding ports in the port scanner's scanned dictionary
      self.is_ps_all=False  # set flag to indicate port scanning process has finished

  def update_data_transfered(self):
      for device in self.devices:  # loop through all devices
        if device.ip in self.net_transfer.devices.keys():  # if the device's IP address is in the network transfer's devices dictionary
          device.data_transfered=self.net_transfer.devices[device.ip]  # set the device's data transferred to the corresponding value in the dictionary

  def arp_scanner(self,ip_list):
    # create a ARP packet to broadcast to all devices on the network
    p=Ether(dst='FF:FF:FF:FF:FF:FF')/ARP()

    # iterate over the list of IP addresses to scan
    for ip in ip_list:
        # check if stop flag has been set
        if self.stop_flag:
          return
        # set target IP address for ARP packet
        target_ip=ip
        p[ARP].pdst=target_ip
        # send the ARP packet and wait for a response
        response=srp1(p,timeout=2.5,verbose=0)
        # check if stop flag has been set
        if self.stop_flag:
          return
        # if there was a response, store the IP-to-MAC mapping in results dictionary
        if response:
          with self.lock:
            self.results[response[ARP].psrc]=response[ARP].hwsrc

        # increment the count of finished scans
        self.finished_scanning_count+=1

  def close_all_tools(self):
    # set scanning flag to False for all network tools
    self.name_resolver.scanning=False
    self.ps.scanning=False
    self.net_transfer.scanning=False
    self.ps.port_con.scanning=False

  def parse_ip_input(self,ip_input):
      # If the IP input contains any letters, it's invalid
      if  re.search("[a-z]", ip_input) or re.search("[A-Z]", ip_input):
          return False
          
      try:
        ip_list = []
        
        # Split the IP input into separate ranges
        ip_ranges = ip_input.split(',')

        # For each range, determine if it's a single IP or a range of IPs
        for ip_range in ip_ranges:
            if '-' in ip_range:
                # If it's a range, split the range into start and end IPs
                start_ip, end_num = ip_range.split('-')
                start_ip_parts = start_ip.split('.')
                # Ensure that each part of the start IP is valid
                for part in start_ip_parts:
                  if len(part)==0:
                      return False
                
                # Calculate the difference between the start and end IPs
                differnece=int(end_num)-int(start_ip_parts[-1])
                # Ensure that each part of the start IP has leading zeros if necessary
                for i in range(len(start_ip_parts)):
                  while len(start_ip_parts[i])<3:
                      start_ip_parts[i]='0'+start_ip_parts[i]
                # Convert the start IP to an integer
                start_int = int(''.join(start_ip_parts))
                # Generate each IP address in the range
                for i in range(start_int, start_int+differnece+1):
                    i=str(i)
                    # Remove any leading zeros and add the IP to the list of IPs to scan
                    ip_list.append(f"{i[:3].removeprefix('0').removeprefix('0')}.{i[3:6].removeprefix('0').removeprefix('0')}.{i[6:9].removeprefix('0').removeprefix('0')}.{i[9:12].removeprefix('0').removeprefix('0')}")
            else:
                # If it's a single IP, add it to the list of IPs to scan
                ip_list.append(ip_range)
        
        if len(ip_list)==0:
          # If the list of IPs to scan is empty, the input is invalid
          return False

        # Check that each IP address is valid
        # An IP address is valid if it has four parts separated by periods, each part is a number between 1 and 255,
        # and the IP address is not 0.0.0.0 and is on the local network
        for ip in ip_list:
          if ip.count(".")!=3 or not self.is_in_lan(ip) or '0' in ip.split('.'):
            return False
          socket.inet_aton(ip)

        # Save the list of IPs to scan and return True to indicate success
        self.ips_to_scan=ip_list
        return True
      
      except:
        # If there is an exception, the input is invalid
        return False
    
  def is_in_lan(self,ip):
      # Get network information
      net_info=get_net_info.get_ip_info()
      my_ip=self.my_ip.split('.')
      ip=ip.split('.')
      subnet_mask=net_info[2].split('.')

      ip=list(map(int,ip))
      my_ip=list(map(int,my_ip))
      subnet_mask=list(map(int,subnet_mask))

      # Check if the IP address is on the local network
      on_lan=True
      for i in range(len(ip)):
          if ip[i]&subnet_mask[i]!=my_ip[i]&subnet_mask[i]:
              on_lan=False
      
      return on_lan
