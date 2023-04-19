import speedtest
import time
import os
import socket
import get_net_info
import threading

class traffic_tester():
    def __init__(self):
        self.download=0
        self.upload=0
        self.ping=0
        self.latency=0
        self.bandwidth=0
        self.scanning=False

    def full_test(self):
        self.scanning=True
        thr1=threading.Thread(target=self.network_speed_test)
        thr2=threading.Thread(target=self.network_latency)
        thr3=threading.Thread(target=self.network_bandwidth)
        threads=[thr1,thr2,thr3]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        self.scanning=False
        
    def network_speed_test(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000
            upload_speed = st.upload() / 1_000_000
            ping = st.results.ping
            self.download=round(download_speed,1)
            self.upload=round(upload_speed,1)
            self.ping=round(ping,1)
        except:
            self.download='error'
            self.upload='error'
            self.ping='error'

    def network_latency(self):
        target_ip=get_net_info.get_ip_info()[1] #router
        results=[] 
        while len(results)<10:
            try:
                start = time.time()
                os.system("ping " + target_ip + " -n 1 >nul")
                end = time.time()
                latency = (end - start)*1000
                results.append(latency)
                time.sleep(0.1)
            except:
                time.sleep(0.1)
                pass

        self.latency=round(sum(results)/len(results),1)

    def network_bandwidth(self):
        target_ip=get_net_info.get_ip_info()[1] #router
        packet_size=300
        packet_count=200
        results=[]
        while len(results)<10:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
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
            s.shutdown(socket.SHUT_WR)
            end = time.time()
            try:
                results.append(((packet_size * packet_count) / (end - start))/1_000_000)
                time.sleep(0.1)
            except ZeroDivisionError:
                time.sleep(0.1)
                pass
        if sum(results)==0 or len(results)==0:
            self.bandwidth='error'
        else:
            self.bandwidth=round(sum(results)/len(results),1)