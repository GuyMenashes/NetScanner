import subprocess
from netaddr import IPNetwork

def get_ip_info()->tuple[str,str,str,list[str]]:
  '''
    returns a tuple containing (ip,defult_gateway,subnet_mask,list of all ips in network)
  '''
  command = ['ipconfig', '/all']

  output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output = output.stdout.decode(encoding='utf-8',errors='ignore')
  output=output[output.find('Wi-Fi:'):]

  lines = output.split('\n')
  for line in lines:
      if 'Subnet Mask' in line:
          subnet_mask = line.split(':')[-1].strip()
      elif 'IPv4' in line:
          ip = (line.split(':')[-1].strip()).replace('(Preferred)','')
      elif 'Default Gateway' in line:
          defult_gateway = line.split(':')[-1].strip()

  network = IPNetwork('/'.join([ip, subnet_mask]))
  generator = network.iter_hosts()
  ip_list=[]
  for i in generator:
      ip_list.append(str(i))

  return ip,defult_gateway,subnet_mask,ip_list

def get_wifi_password():
    command=['netsh', 'wlan', 'show', 'interfaces']

    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
    output = output.stdout.decode(encoding='utf-8',errors='ignore')
    lines=output.split('\n')
    name=None
    for line in lines:
        if 'Profile' in line:
                name = line.split(':')[-1].strip()
    if not name:
        return 'name not found'
    
    command = 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    txt = result.stdout.decode('utf-8').split('=======================================================================')
    for i in range(len(txt)):
        if f'Profile {name} on interface' in txt[i]:
             net=txt[i+1]

    net=net.split('\n')
    password=None
    for line in net:
        if 'Key Content' in line:
             password=line.split(':')[-1].strip()
    
    if not password:
         return 'Open network, no password'
    
    return password