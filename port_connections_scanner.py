from scapy.all import *  # import the necessary Scapy module
from get_net_info import *  # import the custom module that contains get_ip_info() function


class port_connections_scanner():

    def __init__(self):
        self.connections={}  # initialize an empty dictionary to store the port connections
        self.scanning=True  # a flag to indicate if scanning is still ongoing
        self.my_ip=get_ip_info()[0]  # get the IP address of the current device

    def run_scanner(self):
        # Start sniffing packets and apply packet_filter() as a filter and packet_handler() as a callback function
        sniff(lfilter=self.packet_filter, prn=self.packet_handler, store=False)

    # Define a function to handle incoming packets
    def packet_handler(self,packet):
        if not self.scanning:
            sys.exit()  # if scanning is done, stop sniffing packets and exit the program
            
        # check if the packet is destined to a device in the local network and get the IP address and TCP port number
        if self.is_in_lan(packet[IP].dst):
            # check if a key exists in the connections dictionary
            if self.connections.get((packet[IP].dst,packet[TCP].dport)):
                # check if the source IP address and source port number are not already in the list
                if (packet[IP].src,packet[TCP].sport) not in self.connections[(packet[IP].dst,packet[TCP].dport)]:
                    # if the IP address and port number are not in the list, append them
                    self.connections[(packet[IP].dst,packet[TCP].dport)].append((packet[IP].src,packet[TCP].sport))
            else:
                # if the key doesn't exist, add it to the dictionary with the source IP and port number
                self.connections[(packet[IP].dst,packet[TCP].dport)]=[(packet[IP].src,packet[TCP].sport)]
        # check if the packet is from a device in the local network and get the IP address and TCP port number
        if self.is_in_lan(packet[IP].src):
            # check if a key exists in the connections dictionary
            if self.connections.get((packet[IP].src,packet[TCP].sport)):
                # check if the destination IP address and destination port number are not already in the list
                if (packet[IP].dst,packet[TCP].dport) not in self.connections[(packet[IP].src,packet[TCP].sport)]:
                    # if the IP address and port number are not in the list, append them
                    self.connections[(packet[IP].src,packet[TCP].sport)].append((packet[IP].dst,packet[TCP].dport))
            else:
                # if the key doesn't exist, add it to the dictionary with the destination IP and port number
                self.connections[(packet[IP].src,packet[TCP].sport)]=[(packet[IP].dst,packet[TCP].dport)]

    def packet_filter(self,packet):
        # Check if the scan has been stopped
        if not self.scanning:
            sys.exit()
            
        # Check if the packet is an IP packet
        if packet.haslayer(IP):
            # Check if the packet is a TCP packet and is from/to a device on the same subnet as our device
            if packet.haslayer(TCP) and (self.is_in_lan(packet[IP].dst) or self.is_in_lan(packet[IP].src)):
                # Check if the packet is not from/to our own device
                if not (packet[IP].dst==self.my_ip or packet[IP].src==self.my_ip):
                    # If all conditions are satisfied, return True to indicate that the packet should be captured
                    return True

    # Function to check if the given IP is on the same subnet as our device
    def is_in_lan(self,ip):
        # Get information about our device's IP and subnet mask
        net_info=get_ip_info()
        my_ip=self.my_ip.split('.')
        ip=ip.split('.')
        subnet_mask=net_info[2].split('.')
        
        # Convert the IP and subnet mask to lists of integers
        ip=list(map(int,ip))
        my_ip=list(map(int,my_ip))
        subnet_mask=list(map(int,subnet_mask))

        # Check if the given IP is on the same subnet as our device
        on_lan=True
        for i in range(len(ip)):
            if ip[i]&subnet_mask[i]!=my_ip[i]&subnet_mask[i]:
                on_lan=False
        return on_lan
        
    # Function to get the list of connected devices for the given IP and port
    def get_connected_device(self,ip,port)-> list[tuple[str,int]]|None:
        # Check if the given IP and port are already in the connections dictionary
        value=self.connections.get((ip,port))
        if value:
            # If the IP and port are already in the connections dictionary, return the list of connected devices
            return value
            
        # If the IP and port are not already in the connections dictionary, return None
        return None