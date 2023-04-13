from encrypted_server import encrypted_server
import time
from Controlled import RemoteControlled
import multiprocessing

def listen_for_connections():
    while True:
        server=encrypted_server(11123)
        server.start_server(first_connection=True)
        answer=input(f'{server.addr[0]} wants to connect to you, do you allow him? y/n ')
        if answer=='y':
            print('approved')
            server.send('approved')
            break
        else:
            server.send('denied')
            time.sleep(1)
            print('denied')
            del server

    print('connecting')
    RemoteControlled()

if __name__=='__main__':
    listen_for_connections()


