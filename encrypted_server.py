import rsa
from cryptography.fernet import Fernet
import socket

class encrypted_server:
    def __init__(self,port):
        #establish connection
        self.server_socket=socket.socket()
        self.server_socket.bind(('0.0.0.0',port))
        self.server_socket.listen(2)

    def start_server(self,first_connection=True):
        self.client,self.addr=self.server_socket.accept()
        if first_connection:
            self.generate_keys()
            self.pubKey,self.privKey,self.symKey=self.loadKeys()

            self.client.send(self.pubKey.save_pkcs1('PEM'))
            self.controller_pubKey=rsa.PublicKey.load_pkcs1(self.client.recv(1024))
            self.client.send(rsa.encrypt(self.symKey,self.controller_pubKey))
        else:
            self.symKey=self.loadKeys()[2]

        self.encoder=Fernet(self.symKey)
        
    def send(self,text,isBytes=False):
        if not isBytes:
            text=bytes(text,encoding='utf-8')
        enc_text=self.encoder.encrypt(text)
        self.client.send(enc_text)
    
    def recieve(self,size=1024,isBytes=False):
        enc_recieved=self.client.recv(size)
        if not enc_recieved:
            return None
        try:
            data=self.encoder.decrypt(enc_recieved)
        except:
            return None
        if isBytes:
            return data
        return data.decode()

    def generate_keys(self):
        (pubKey,privKey)=rsa.newkeys(1024) 
        with open('keys/publicKey.pem', 'wb') as f:
            f.write(pubKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as f:
            f.write(privKey.save_pkcs1('PEM'))
        symKey=Fernet.generate_key()
        with open('keys/symKey.pem','wb') as f:
            f.write(symKey)

    def loadKeys(self):
        with open('keys/publicKey.pem', 'rb') as f:
            pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open('keys/privateKey.pem', 'rb') as f:
            privKey = rsa.PrivateKey.load_pkcs1(f.read())
        with open('keys/symkey.pem', 'rb') as f:
            symKey=f.read()

        return pubKey, privKey,symKey