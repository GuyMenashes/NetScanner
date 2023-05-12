from mac_vendor import get_mac_vendor # imports function to get mac vendor information from a mac address
from get_net_info import * # imports functions to get network information
from port_scanner import PortScanner # imports PortScanner class for scanning ports on a device
from Hostname_resolver import Hostname_Resolver # imports Hostname_Resolver class for resolving IP addresses to hostnames

class Device():
    def __init__(self, ip, mac, ps: PortScanner, name_resolver: Hostname_Resolver):
        # initializes a new instance of the Device class with the given IP address, MAC address, PortScanner object and Hostname_Resolver object
        self.ip = ip
        self.mac = mac
        self.is_alive = True # initializes the is_alive attribute to True
        self.mac_vendor = get_mac_vendor(mac) # retrieves the mac vendor information from the given mac address
        self.name = ip # initializes the name attribute to the given IP address
        self.is_defult_gateway = ip == get_ip_info()[1] # determines if the given IP address is the default gateway for the network
        self.data_transfered = 0 # initializes the data_transfered attribute to 0
        self.ports = {} # initializes the ports dictionary to an empty dictionary
        self.port_scanner = ps # initializes the port_scanner attribute to the given PortScanner object
        self.name_resolver = name_resolver # initializes the name_resolver attribute to the given Hostname_Resolver object
        self.currently_port_scanning = False # initializes the currently_port_scanning attribute to False

    def __repr__(self):
        # represents the Device object as a string
        f = "name                     ip              mac               mac vendor\n"
        f += f"{self.name:<25}{self.ip:<16}{self.mac:<18}{self.mac_vendor:<16}\n"
        f += f"Data Transfered: {self.data_transfered} bytes\n"
        for port in self.ports.keys():
            info = self.ports[port]
            if info[1]:
                f += f"port {port} is open and talking to {','.join(f'{connection[0]}:{connection[1]}' for connection in info[1])}\n"
            else:
                f += f"port {port} is open, "
            if info[0]:
                f += f"this port is usually used for: {info[0]}\n"
        
        return f.strip('\n')
    
    def popular_port_scan(self):
        # scans the most commonly used ports for the device and stores the result in the ports dictionary
        self.currently_port_scanning = True
        self.port_scanner.popular_scan(self.ip, 'detailed')
        self.ports = self.port_scanner.scanned[self.ip]
        self.currently_port_scanning = False
    
    def intense_port_scan(self, start, end, chunk, accuracy):
        # scans a range of ports for the device and stores the result in the ports dictionary
        self.currently_port_scanning = True
        self.port_scanner.intense_scan(self.ip, start, end, chunk, accuracy, 'detailed')
        self.ports = self.port_scanner.scanned[self.ip]
        self.currently_port_scanning = False
    
    def resolve_name(self):
        # resolves the IP address of the device to a hostname and updates the name attribute
        self.name_resolver.resolve_ip(self.ip)
        if self.ip in self.name_resolver.devices.keys():
                self.name = self.name_resolver.devices[self.ip]
                
    def get_port_desc(self):
        row=["","","",""] # Create a list to hold the row values for each port
        pos=0 # Initialize the position variable
        for port in self.ports.keys(): # Iterate through the dictionary of ports
            info=self.ports[port] # Get the information for the current port
            if info[1]: # If the port is open and has connections
                row[pos]+=f"{port}(->{','.join(f'{connection[0]}:{connection[1]}' for connection in info[1])})" # Add the port number and the connections to the current row
            else:
                row[pos]+=f"{port}" # If the port is open but has no connections, add only the port number to the current row
            if info[0]: # If there is a description for the port
                row[pos]+=':' # Add a colon to separate the port number from the description
                row[pos]+=info[0] # Add the description to the current row
                if pos<3: # If the current row is not the last row
                    pos+=1 # Move to the next row
            else:
                row[pos]+=', ' # If there is no description, add a comma and a space to separate the port number from the next port
                if len(row[pos])>20: # If the current row has more than 20 characters
                    pos+=1 # Move to the next row
                
        return row # Return the list of row values for each port