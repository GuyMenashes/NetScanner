from scapy.all import *

p:Packet=Ether(dst='ff:ff:ff:ff:ff:ff')
while True:
   sendp(p,verbose=0)