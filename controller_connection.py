from encrypted_client import encrypted_client
from Controller import RemoteController
import time

ip='192.168.68.100'
client=encrypted_client(ip,11123)
try:
    client.run_server()
except:
    print('couldnt connect')
    quit()
respense=client.recieve()
if respense=='approved':
    print('connecting')
    time.sleep(2)
    RemoteController(ip)
else:
    print('denied')