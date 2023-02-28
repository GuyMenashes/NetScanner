from mac_vendor import get_mac_vendor
from get_net_info import *
from port_scanner import PortScanner
from Hostname_resolver import Hostname_Resolver

class Device():
    def __init__(self,ip,mac,ps:PortScanner,name_resolver:Hostname_Resolver):
        self.ip=ip
        self.mac=mac
        self.is_alive=True
        self.mac_vendor=get_mac_vendor(mac)
        self.name=ip
        self.is_defult_gateway=ip==get_ip_info()[1]
        self.data_transfered=0
        self.ports={}
        self.port_scanner=ps
        self.name_resolver=name_resolver
        self.currently_port_scanning=False

    def __repr__(self):
        f=  "name                     ip              mac               mac vendor\n"
        f+=f"{self.name:<25}{self.ip:<16}{self.mac:<18}{self.mac_vendor:<16}\n"
        f+=f"Data Transfered: {self.data_transfered} bytes\n"
        for port in self.ports.keys():
            info=self.ports[port]
            if info[1]:
                f+=f"port {port} is open and talking to {','.join(f'{connection[0]}:{connection[1]}' for connection in info[1])}\n"
            else:
                 f+=f"port {port} is open, "
            if info[0]:
                f+=f"this port is usually used for: {info[0]}\n"
        
        return f.strip('\n')
    
    def popular_port_scan(self):
        self.currently_port_scanning=True
        self.port_scanner.popular_scan(self.ip,'detailed')
        self.ports=self.port_scanner.scanned[self.ip]
        self.currently_port_scanning=False
    
    def intense_port_scan(self,start,end,chunk,accuracy):
        self.currently_port_scanning=True
        self.port_scanner.intense_scan(self.ip,start,end,chunk,accuracy,'detailed')
        self.ports=self.port_scanner.scanned[self.ip]
        self.currently_port_scanning=False
    
    def resolve_name(self):
        self.name_resolver.resolve_ip(self.ip)
        if self.ip in self.name_resolver.devices.keys():
                self.name=self.name_resolver.devices[self.ip]

    def get_port_desc(self):
        row=["","","",""]
        pos=0
        for port in self.ports.keys():
            info=self.ports[port]
            if info[1]:
                row[pos]+=f"{port}(->{','.join(f'{connection[0]}:{connection[1]}' for connection in info[1])})"
            else:
                row[pos]+=f"{port}"
            if info[0]:
                row[pos]+=':'
                row[pos]+=info[0]
                if pos<3:
                    pos+=1
            else:
                row[pos]+=', '
                if len(row[pos])>20:
                    pos+=1
            
        return row
