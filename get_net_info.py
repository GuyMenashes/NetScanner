# Import necessary libraries
import subprocess
from netaddr import IPNetwork
import re

def get_ip_info() -> tuple[str,str,str,list[str]]:
    """
    Returns a tuple containing (ip, defult_gateway, subnet_mask, list of all ips in network)
    """
    # Command to get IP configuration information in Windows
    command = ['ipconfig', '/all']

    # Execute the command and capture the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = output.stdout.decode(encoding='utf-8', errors='ignore')

    # Split the output by lines and iterate over each line to find the necessary information
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if 'Subnet Mask' in line:
            # Extract the subnet mask
            subnet_mask = line.split(':')[-1].strip()
        elif 'IPv4' in line:
            # Extract the IP address
            ip = (line.split(':')[-1].strip())[:line.split(':')[-1].strip().find("(")]
        elif 'Default Gateway' in line:
            # Extract the default gateway
            if not re.search("[0-9]", line):
                continue
            if re.search("[a-z]", line):
                line = lines[i+1]
            defult_gateway = line.split(':')[-1].strip()
            break

    # Use the IP address and subnet mask to generate a network object
    network = IPNetwork('/'.join([ip, subnet_mask]))
    # Iterate over each host in the network and add it to a list of IPs
    generator = network.iter_hosts()
    ip_list = []
    for i in generator:
        ip_list.append(str(i))

    # Return the necessary information as a tuple
    return ip, defult_gateway, subnet_mask, ip_list