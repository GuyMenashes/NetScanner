from encrypted_client import encrypted_client
from Controller import RemoteController
import time

client=encrypted_client('192.168.1.243',11123)
client.run_server()
respense=client.recieve()
if respense=='approved':
    print('connecting')
    time.sleep(2)
    RemoteController('192.168.1.243')
else:
    print('denied')