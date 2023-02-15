from mac_vendor import get_mac_vendor
from get_net_info import *

class Device():
    def __init__(self,ip,mac):
        self.ip=ip
        self.mac=mac
        self.is_alive=True
        self.mac_vendor=get_mac_vendor(mac)
        self.name=ip
        self.is_defult_gateway=ip==get_ip_info()[1]
        self.data_transfered=0
        self.ports={}

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