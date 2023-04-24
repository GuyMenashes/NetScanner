from scapy.all import *
import get_net_info

class Hostname_Resolver():
    def __init__(self):
        self.devices={}
        self.scanning=True
        self.my_ip=get_net_info.get_ip_info()[0]
    
    def start_mdsn_sniffing(self):
        sniff(lfilter=self.is_mdns,prn=self.mdns_resolve_name,store=False)

    def is_mdns(self,p):
        if not self.scanning:
            sys.exit()
        return IP in p and p[IP].dst=='224.0.0.251' and DNS in p and DNSRR in p[DNS] and p[DNS][DNSRR].type==12

    def mdns_resolve_name(self,p):
        if p[IP].src==self.my_ip:
            return
        name=p[DNS][DNSRR].rrname.decode()

        if 'in-addr' in name:
            name=None

        elif name=='_googlecast._tcp.local.':
            name=p[DNS][DNSRR].rdata.decode()
            name=name[:name.rfind('-')]
        
        elif name.startswith('_'):
            name=None
        
        elif '_tcp' in name:
            name=name[:name.find('._')]
        
        elif name==p[IP].src:
            name=None

        if name:
            self.devices[p[IP].src]=name
    
    def resolve_ip(self,ip):
        command = ['ping', '-a','-n','1','-w','0',ip]

        # Run the command and get the output
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            return
        output = output.stdout.decode(encoding='utf-8',errors='ignore')
        output=output.split('\n')[1]
        if '['  in output:
            output=output.removeprefix('Pinging ')
            self.devices[ip]=output[:output.find('[')].removesuffix('.lan ').removesuffix('.home ')

    def get_name(self,ip):
        return self.devices.get(ip)