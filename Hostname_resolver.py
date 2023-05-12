from scapy.all import * # import scapy library for packet sniffing
import get_net_info # import a user-defined module 'get_net_info'

class Hostname_Resolver():
    def __init__(self):
        self.devices={} # initialize an empty dictionary to hold devices' names and IP addresses
        self.scanning=True # set scanning flag to True
        self.my_ip=get_net_info.get_ip_info()[0] # get local IP address from get_net_info module's function
    
    def start_mdsn_sniffing(self):
        sniff(lfilter=self.is_mdns,prn=self.mdns_resolve_name,store=False) # start sniffing mDNS packets and process them using mdns_resolve_name method

    def is_mdns(self,p):
        if not self.scanning:
            sys.exit() # if scanning flag is False, exit the program
        return IP in p and p[IP].dst=='224.0.0.251' and DNS in p and DNSRR in p[DNS] and p[DNS][DNSRR].type==12 # check if packet is a multicast DNS query and return a boolean

    def mdns_resolve_name(self,p):
        if p[IP].src==self.my_ip:
            return # if packet is from localhost, return
        name=p[DNS][DNSRR].rrname.decode() # get the DNS record name from packet's DNS resource record

        if 'in-addr' in name:
            name=None # ignore the record if it contains 'in-addr'

        elif name=='_googlecast._tcp.local.':
            name=p[DNS][DNSRR].rdata.decode() # extract Google Cast device name
            name=name[:name.rfind('-')]

        elif name.startswith('_'):
            name=None # ignore the record if it starts with underscore

        elif '_tcp' in name:
            name=name[:name.find('._')] # extract name if it contains '_tcp'

        elif name==p[IP].src:
            name=None # ignore if the name is the same as the IP address

        if name:
            self.devices[p[IP].src]=name # if name is not None, add the IP and name to the devices dictionary
    
    def resolve_ip(self,ip):
        command = ['ping', '-a','-n','1','-w','0',ip] # construct a command to run 'ping' with options to resolve hostname

        # Run the command and get the output
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            return # if the command failed, return
        output = output.stdout.decode(encoding='utf-8',errors='ignore') # decode output to string
        output=output.split('\n')[1] # extract the second line from output
        if '['  in output:
            output=output.removeprefix('Pinging ')
            self.devices[ip]=output[:output.find('[')].removesuffix('.lan ').removesuffix('.home ') # extract hostname from output and add to the devices dictionary
    
    def get_name(self,ip):
        return self.devices.get(ip) # get device name associated with an IP address from the devices dictionary