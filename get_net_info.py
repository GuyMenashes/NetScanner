import subprocess
from netaddr import IPNetwork
import re

def get_ip_info()->tuple[str,str,str,list[str]]:
  '''
    returns a tuple containing (ip,defult_gateway,subnet_mask,list of all ips in network)
  '''
  command = ['ipconfig', '/all']

  output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output = output.stdout.decode(encoding='utf-8',errors='ignore')
  output=output[output.find('Wi-Fi:'):]

  lines = output.split('\n')
  for i,line in enumerate(lines):
      if 'Subnet Mask' in line:
          subnet_mask = line.split(':')[-1].strip()
      elif 'IPv4' in line:
          ip = (line.split(':')[-1].strip())[:line.split(':')[-1].strip().find("(")]
      elif 'Default Gateway' in line:
          if re.search("[a-z]", line):
              line=lines[i+1]
          defult_gateway = line.split(':')[-1].strip()

  network = IPNetwork('/'.join([ip, subnet_mask]))
  generator = network.iter_hosts()
  ip_list=[]
  for i in generator:
      ip_list.append(str(i))

  return ip,defult_gateway,subnet_mask,ip_list