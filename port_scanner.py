import threading
import time
import socket
from port_connections_scanner import port_connections_scanner

class PortScanner():
    def __init__(self):
        self.scanned={}
        self.scanning=True
        self.port_con=port_connections_scanner()
        port_con_thr=threading.Thread(target=self.port_con.run_scanner)
        port_con_thr.start()
        self.port_descriptions = {
        20: "FTP (File Transfer Protocol) data transfer",
        21: "FTP (File Transfer Protocol) control",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Simple Mail Transfer Protocol)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Hypertext Transfer Protocol)",
        110: "POP3 (Post Office Protocol version 3)",
        119: "NNTP (Network News Transfer Protocol)",
        123: "NTP (Network Time Protocol)",
        143: "IMAP (Internet Message Access Protocol)",
        179: "BGP (Border Gateway Protocol)",
        443: "HTTPS (HTTP Secure)",
        465: "SMTPS (SMTP Secure)",
        587: "Submission (SMTP for email submission)",
        993: "IMAPS (IMAP Secure)",
        995: "POP3S (POP3 Secure)",
        1433: "Microsoft SQL Server",
        3389: "RDP (Remote Desktop Protocol)",
        8000:"Commonly used as an alternate HTTP port",
        8080: "HTTP alternate (commonly used for web servers)",
        8443: "HTTPS alternate",
        }

    def scanner(self,ip,start,end,results,wait_time):
        for port in range(start, end):
            if not self.scanning:
                sys.exit()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(wait_time)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    with self.lock:
                        results.append(port)
                sock.close()
            except socket.gaierror:
                print("Host could not be resolved.")
            except socket.error:
                print("Could not connect to server.")

    def intense_scan(self,ip,start,end,chunk_size,accuracy,mode='simple')->list|dict:
        ''' Perform a scan on the port range provided. Every thread gets the number of ports specified in the chunk size parameter.
        Parameters
        ----------
        start : int 
            the start of the port range

        end : int 
            the end of the port range

        chunk_size : int 
            the amount of ports each thread gets

        mode : str\n
            if mode is "simple" returns list of only port numbers\n
            if mode is "detailed" return dictionary of port numbers and descriptions
        '''
        if mode not in ['simple','detailed']:
            return 'invalid mode'
                
        wait_time=accuracy*0.03
        
        results=[]
        
        self.lock=threading.Lock()
        threads=[]
        for i in range(start, end, chunk_size):
            start = i
            end = i + chunk_size
            t = threading.Thread(target=self.scanner, args=(ip,start, end,results,wait_time))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()       

        if not self.scanning:
            sys.exit()

        if mode=='simple':
            self.scanned[ip]=results
        
        else:
            #ip={port1:(desc,[(ip,port),(ip,port)...],port2:(desc,[(ip,port),(ip,port)...]...}
            self.scanned[ip]={}
            for port in results:
                connected=self.port_con.get_connected_device(ip,port)
                if port in self.port_descriptions.keys():
                    if not connected:
                        self.scanned[ip][port]=(self.port_descriptions[port],None)
                    else:
                        connections=[]
                        for connection in connected:
                            connections.append(connection[0],connection[1])

                        self.scanned[ip][port]=(self.port_descriptions[port],connections) 
                else: 
                    if not connected:
                        self.scanned[ip][port]=(None,None)
                    else:
                        connections=[]
                        for connection in connected:
                            connections.append(connection[0],connection[1])

                        self.scanned[ip][port]=(None,connections)

    def popular_scan(self,ip,mode='simple')->list|dict:
        ''' Perform a scan on the ports used by common network protocols
        Parameters
        ----------
        mode : str
            if mode is "simple" returns list of only port numbers\n
            if mode is "detailed" return dictionary of port numbers and descriptions
        '''
        if mode not in ['simple','detailed']:
            return 'invalid mode' 
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 179, 443, 465, 500, 587, 993, 995,1433, 3389,8000,8080,8443]
        results=[]
        for port in ports:
            if not self.scanning:
                sys.exit()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    results.append(port)
                sock.close()
            except socket.gaierror:
                print("Host could not be resolved.")
            except socket.error:
                print("Could not connect to server.")

        if mode=='simple':
            self.scanned[ip]=results
        
        #ip={port1:(desc,[(ip,port),(ip,port)...],port2:(desc,[(ip,port),(ip,port)...]...}
        else:
            self.scanned[ip]={}
            for port in results:
                connected=self.port_con.get_connected_device(ip,port)
                if not connected:
                    self.scanned[ip][port]=(self.port_descriptions[port],None)
                else:
                    connections=[]
                    for connection in connected:
                        connections.append(connection[0],connection[1])

                    self.scanned[ip][port]=(self.port_descriptions[port],connections)