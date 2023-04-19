from encrypted_server import encrypted_server
import time
from Controlled import RemoteControlled

def listen_for_connections():
    while True:
        server=encrypted_server(11123)
        server.start_server(first_connection=True)
        info=server.recieve().split(',')
        quality=int(info[2])
        answer=input(f'ip: {server.addr[0]}, name:{info[0]} wants to connect to you for the reason: {info[1]}, do you allow him? y/n ')
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
    RemoteControlled(quality)

if __name__=='__main__':
    listen_for_connections()


