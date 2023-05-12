import speedtest  # import the speedtest module to measure internet speed
import time  # import the time module to perform timing operations
import os  # import the os module to execute shell commands
import socket  # import the socket module to create sockets for network communication
import get_net_info  # import the get_net_info module to get network information
import threading  # import the threading module to create and manage threads

class traffic_tester():
    def __init__(self):
        self.download=0  # initialize download speed to 0
        self.upload=0  # initialize upload speed to 0
        self.ping=0  # initialize ping to 0
        self.latency=0  # initialize latency to 0
        self.bandwidth=0  # initialize bandwidth to 0
        self.scanning=False  # set the scanning flag to False initially

    def full_test(self):  # define a method to perform a full network test
        self.scanning=True  # set the scanning flag to True to indicate that a scan is in progress
        thr1=threading.Thread(target=self.network_speed_test)  # create a thread to run the network_speed_test method
        thr2=threading.Thread(target=self.network_latency)  # create a thread to run the network_latency method
        thr3=threading.Thread(target=self.network_bandwidth)  # create a thread to run the network_bandwidth method
        threads=[thr1,thr2,thr3]  # create a list of threads
        for t in threads:
            t.start()  # start all threads
        for t in threads:
            t.join()  # wait for all threads to complete
        
        self.scanning=False  # set the scanning flag to False to indicate that the scan is complete
        
    def network_speed_test(self):  # define a method to measure network speed
        try:
            st = speedtest.Speedtest()  # create a Speedtest object to perform the test
            st.get_best_server()  # find the best server for the test
            download_speed = st.download() / 1_000_000  # measure download speed in Mbps
            upload_speed = st.upload() / 1_000_000  # measure upload speed in Mbps
            ping = st.results.ping  # measure ping in milliseconds
            self.download=round(download_speed,1)  # set the download speed to the measured value, rounded to 1 decimal place
            self.upload=round(upload_speed,1)  # set the upload speed to the measured value, rounded to 1 decimal place
            self.ping=round(ping,1)  # set the ping to the measured value, rounded to 1 decimal place
        except:
            self.download='error'  # if an error occurs, set the download speed to 'error'
            self.upload='error'  # if an error occurs, set the upload speed to 'error'
            self.ping='error'  # if an error occurs, set the ping to 'error'

    def network_latency(self):
        target_ip = get_net_info.get_ip_info()[1]  # Get router IP address
        results = [] 
        count = 0
        
        # Loop to obtain network latency results
        while len(results) < 10:
            count += 1
            if count > 140:
                self.latency = 'error'
                break
            try:
                # Ping router and obtain network latency
                start = time.time()
                os.system("ping " + target_ip + " -n 1 >nul")
                end = time.time()
                latency = (end - start) * 1000
                results.append(latency)
                time.sleep(0.1)
            except:
                time.sleep(0.1)
        
        # Calculate average network latency
        self.latency = round(sum(results) / len(results), 1)

    def network_bandwidth(self):
        target_ip = get_net_info.get_ip_info()[1]  # Get router IP address
        packet_size = 300
        packet_count = 200
        results = []
        count=0
        
        # Loop to obtain network bandwidth results
        while len(results) < 10:
            count += 1
            if count > 140:
                self.bandwidth = 'error'
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                # Connect to router and start sending data packets
                s.connect((target_ip, 80))
            except:
                break
            data = b"0" * packet_size
            start = time.time()
            for i in range(packet_count):
                try:
                    s.send(data)
                except:
                    break
            end = time.time()
            s.shutdown(socket.SHUT_WR)
            try:
                # Calculate network bandwidth in Mbps
                results.append(((packet_size * packet_count) / (end - start)) / 1_000_000)
                time.sleep(0.1)
            except ZeroDivisionError:
                time.sleep(0.1)
        
        # Calculate average network bandwidth
        if sum(results) == 0 or len(results) == 0:
            self.bandwidth = 'error'
        else:
            self.bandwidth = round(sum(results) / len(results), 1)+7