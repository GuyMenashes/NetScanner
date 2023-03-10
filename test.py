import pyshark
from pyshark.tshark.tshark import get_all_tshark_interfaces_names

for i,name in enumerate(get_all_tshark_interfaces_names()):
    if 'Wi-Fi' in name:
       interface = get_all_tshark_interfaces_names()[i-1]

# Define a list of malware signatures to look for in the traffic
signatures = [
    'ET MALWARE Possible AgentTesla CnC Beacon',
    'ET MALWARE Trickbot CnC Beacon',
    'ET MALWARE Emotet CnC Beacon',
    'ET MALWARE Lokibot CnC Beacon',
    'ET MALWARE ZLoader CnC Beacon',
    'ET MALWARE Ursnif CnC Beacon',
    'ET MALWARE Dridex CnC Beacon',
    'ET MALWARE Qakbot CnC Beacon',
    'ET MALWARE SmokeLoader CnC Beacon',
    'ET MALWARE Ramnit CnC Beacon',
    'ET MALWARE Nanocore CnC Beacon',
    'ET MALWARE Formbook CnC Beacon',
    'ET MALWARE Pony CnC Beacon',
    'ET TROJAN APT32 Downloader',
    'ET TROJAN APT32 CnC Beacon',
    'ET TROJAN APT37 CnC Beacon',
    'ET TROJAN APT39 CnC Beacon',
    'ET TROJAN APT41 CnC Beacon',
    'ET TROJAN Dridex CnC Beacon',
    'ET TROJAN Emotet CnC Beacon',
    'ET TROJAN Gootkit CnC Beacon',
    'ET TROJAN IcedID CnC Beacon',
    'ET TROJAN Metasploit Meterpreter Payload Detected',
    'ET TROJAN Mirai Variant User-Agent Detected (Linux)',
    'ET TROJAN Mirai Variant User-Agent Detected (Windows)',
    'ET TROJAN Nanocore CnC Beacon',
    'ET TROJAN Necurs CnC Beacon',
    'ET TROJAN NetWire CnC Beacon',
    'ET TROJAN njRAT CnC Beacon',
    'ET TROJAN Pony CnC Beacon',
    'ET TROJAN Qakbot CnC Beacon',
    'ET TROJAN Quasar RAT CnC Beacon',
    'ET TROJAN Remcos RAT CnC Beacon',
    'ET TROJAN SmokeLoader CnC Beacon',
    'ET TROJAN Trickbot CnC Beacon',
    'ET TROJAN Ursnif CnC Beacon',
    'ET TROJAN Vawtrak CnC Beacon',
    'ET TROJAN WastedLocker Ransomware CnC Beacon',
    'ET TROJAN Winnti Variant CnC Beacon',
    'ET TROJAN ZLoader CnC Beacon',
    'ET EXPLOIT Possible MS17-010 SMB RCE Attempt',
    'ET EXPLOIT Possible EternalBlue Exploit M2',
    'ET EXPLOIT Possible BlueKeep MSRC 2019-0708 RDP Remote Windows Kernel Use After Free',
    'ET EXPLOIT Possible BlueKeep Related RDP DoS Attempt'
]

filter_expr = ' or '.join([f'http contains "{sig}"' for sig in signatures])
filter = 'tcp'
# Create a packet capture object using PyShark
capture = pyshark.LiveCapture(interface=interface,capture_filter=filter,display_filter=filter)

# Define a filter to only capture traffic that matches the malware signatures


while True:
    # Start the capture process
    capture.sniff(1)
    try:
        print(capture)
    except :
        pass