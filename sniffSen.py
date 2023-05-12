# Importing required libraries
import threading
from scapy.all import *
from encrypted_server import *
import sys

class SniffSen:
    def __init__(self):
        # initialize instance variables
        self.sniffed_packets=[]
        self.scanning=True
        self.lock=threading.Lock()
        # start a new thread that runs the sniffer method
        threading.Thread(target=self.sniffer).start()

        # create an empty pcap file for saving sniffed packets
        with open('sent_pcap.pcap','wb') as f:
            f.write(b'')

    def send_pcap(self):
        # create a new instance of the encrypted_server class
        self.server=encrypted_server(45689)
        # start the server
        self.server.start_server()

        # get the length of the pcap file
        length=os.path.getsize('sent_pcap.pcap')

        # send the length to the client
        self.server.send(str(length))

        # read the contents of the pcap file
        with self.lock:
            with open('sent_pcap.pcap','rb') as f:
                pcbytes=f.read()

        # receive a confirmation from the client
        self.server.recieve()

        # send the contents of the pcap file in chunks
        if length>600_000:
            for i in range(0,length,500000):
                if i+500000<length:
                    # send a chunk of 500000 bytes
                    self.server.send(pcbytes[i:i+500000],isBytes=True)
                    # receive a confirmation from the client
                    self.server.recieve()
                else:
                    # send the remaining bytes
                    self.server.send(pcbytes[i:],isBytes=True)
                    # receive a confirmation from the client
                    self.server.recieve()
        else:
            # send the whole file
            self.server.send(pcbytes,isBytes=True)
            # receive a confirmation from the client
            self.server.recieve()

        try:
            # close the server socket and client connection
            self.server.server_socket.close()
            self.server.client.close()
        finally:
            # delete the server instance
            del self.server
        
    def sniffer(self):
        # use Scapy's sniff function to sniff packets and call save_packet method for each packet
        sniff(prn=self.save_packet)

    def save_packet(self,p):
        # acquire the lock to access the pcap file
        with self.lock:
            # write the packet to the pcap file
            wrpcap('sent_pcap.pcap', p, append=True)
            # check if the pcap file size exceeds the maximum allowed size
            if os.path.getsize('sent_pcap.pcap')>2_500_000:
                # if so, create a new empty pcap file
                with open('sent_pcap.pcap','wb'):
                    pass
        # if scanning is finished, exit the program
        if not self.scanning:
            sys.exit()