import speedtest
import time
import os
import socket

def network_speed_test():
    st = speedtest.Speedtest()
    st.get_best_server()
    download_speed = st.download() / 1_000_000
    upload_speed = st.upload() / 1_000_000
    ping = st.results.ping
    print(f"Download Speed: {download_speed} Mbps")
    print(f"Upload Speed: {upload_speed} Mbps")
    print(f"Ping:{ping} ms")

def network_latency(target_ip):
    try:
        start = time.time()
        os.system("ping " + target_ip + " -n 1 >nul")
        end = time.time()
        latency = end - start
        print("Latency to", target_ip, ":", latency, "seconds")
    except Exception as e:
        print("Error:", e)


def network_bandwidth(target_ip, packet_size, packet_count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, 80))
        data = b"0" * packet_size
        start = time.time()
        for i in range(packet_count):
            s.send(data)
        s.shutdown(socket.SHUT_WR)
        s.recv(1)
        end = time.time()
        bandwidth = ((packet_size * packet_count) / (end - start))/1_000_000
        print("Bandwidth to", target_ip, ":", bandwidth, "MB/s")