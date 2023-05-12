# Importing necessary modules
import threading
import socket
from port_connections_scanner import port_connections_scanner
import sys

class PortScanner():
    def __init__(self):
        self.scanned = {} # dictionary to store the results of the scan
        self.scanning = True # boolean flag to indicate whether the scan is still ongoing
        self.port_con = port_connections_scanner() # instance of a port_connections_scanner class to get information about established connections
        port_con_thr = threading.Thread(target=self.port_con.run_scanner) # create a thread to run the port_connections_scanner
        port_con_thr.start() # start the thread
        self.port_descriptions = { # dictionary that maps port numbers to descriptions
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

    def scanner(self, ip, start, end, results, wait_time):
        '''Function to scan a range of ports in a separate thread'''
        for port in range(start, end):
            if not self.scanning: # if the scanning flag has been set to False, exit the function
                sys.exit()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a TCP socket
                sock.settimeout(wait_time) # set the timeout for the socket
                result = sock.connect_ex((ip, port)) # try to connect to the specified port
                if result == 0: # if the connection was successful
                    with self.lock: # acquire the lock to update the results list
                        results.append(port)
                sock.close() # close the socket
            except socket.gaierror:
                print("Host could not be resolved.") # handle a DNS resolution error
            except socket.error:
                print("Could not connect to server.") # handle a connection error

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
        # check if mode is valid
        if mode not in ['simple','detailed']:
            return 'invalid mode'
                
        # calculate wait time based on accuracy
        wait_time=accuracy*0.03
        
        # create an empty list to store results
        results=[]
        
        # create a lock for threads
        self.lock=threading.Lock()
        
        # create a thread for each chunk of ports
        threads=[]
        for i in range(start, end, chunk_size):
            start = i
            end = i + chunk_size
            t = threading.Thread(target=self.scanner, args=(ip,start, end,results,wait_time))
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()

        # wait for all threads to finish
        for t in threads:
            t.join()       

        # exit if scanning has stopped
        if not self.scanning:
            sys.exit()

        # store results in scanned dictionary based on mode
        if mode=='simple':
            self.scanned[ip]=results
        
        else:
            # create a dictionary to store port descriptions and connections
            self.scanned[ip]={}
            # iterate through each port in results
            for port in results:
                # get connected devices for the port
                connected=self.port_con.get_connected_device(ip,port)
                # check if port has a description
                if port in self.port_descriptions.keys():
                    # check if port is not connected
                    if not connected:
                        self.scanned[ip][port]=(self.port_descriptions[port],None)
                    else:
                        # create a list of connections
                        connections=[]
                        for connection in connected:
                            connections.append(connection[0],connection[1])
                        # add port description and connections to dictionary
                        self.scanned[ip][port]=(self.port_descriptions[port],connections) 
                else: 
                    # check if port is not connected
                    if not connected:
                        self.scanned[ip][port]=(None,None)
                    else:
                        # create a list of connections
                        connections=[]
                        for connection in connected:
                            connections.append(connection[0],connection[1])
                        # add connections to dictionary
                        self.scanned[ip][port]=(None,connections)

    def popular_scan(self,ip,mode='simple')->list|dict:
        ''' Perform a scan on the ports used by common network protocols
        
        Parameters
        ----------
        ip : str
            IP address to scan
        mode : str
            if mode is "simple" returns list of only port numbers\n
            if mode is "detailed" return dictionary of port numbers and descriptions
        
        Returns
        -------
        list or dict
            A list of open ports if mode is "simple" or a dictionary containing descriptions and connections 
            for each open port if mode is "detailed".
        '''
        # Check if mode is valid
        if mode not in ['simple','detailed']:
            return 'invalid mode' 
        
        # List of common ports to scan
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 179, 443, 465, 500, 587, 993, 995,1433, 3389,8000,8080,8443]
        
        # Initialize results list
        results=[]
        
        # Scan each port in the list
        for port in ports:
            # Check if scanning has been stopped
            if not self.scanning:
                sys.exit()
            
            # Attempt to connect to the port
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

        # If mode is "simple", store results as a list
        if mode=='simple':
            self.scanned[ip]=results
        
        # If mode is "detailed", store results as a dictionary
        else:
            self.scanned[ip]={}
            for port in results:
                # Check if there are any connected devices on the port
                connected=self.port_con.get_connected_device(ip,port)
                if not connected:
                    # If there are no connections, store port description and None for connections
                    self.scanned[ip][port]=(self.port_descriptions[port],None)
                else:
                    # If there are connections, store port description and list of connections
                    connections=[]
                    for connection in connected:
                        connections.append(connection[0],connection[1])
                    self.scanned[ip][port]=(self.port_descriptions[port],connections)
                    