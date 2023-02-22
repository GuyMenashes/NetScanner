import rsa
from cryptography.fernet import Fernet
import socket
import time

class encrypted_client:
    def __init__(self,ip,port):
        #establish connection
        self.ip=ip
        self.port=port
        self.soc=socket.socket()

    def run_server(self,first_connection=True):
        self.soc.connect((self.ip,self.port))

        if first_connection:
            self.generate_keys()
            self.pubKey,self.privKey=self.loadKeys()

            self.server_pubKey=rsa.PublicKey.load_pkcs1(self.soc.recv(1024))
            self.soc.send(self.pubKey.save_pkcs1('PEM'))

            self.symKey=rsa.decrypt(self.soc.recv(1024), self.privKey)

            with open('keys/symKey.pem', 'wb') as f:
                f.write(self.symKey)

        else:
            with open('keys/symKey.pem', 'rb') as f:
                self.symKey=f.read()

        self.encoder=Fernet(self.symKey)
        
    def send(self,text,isBytes=False):
        if not isBytes:
            text=bytes(text,encoding='utf-8')
        enc_text=self.encoder.encrypt(text)
        self.soc.send(enc_text)
    
    def recieve(self,size=1024,isBytes=False):
        enc_recieved=self.soc.recv(size)   
        try:
            data=self.encoder.decrypt(enc_recieved)
            if isBytes:
                return data
            return data.decode()
        except:
            return None
        
    def generate_keys(self):
        (pubKey,privKey)=rsa.newkeys(1024) 
        with open('keys/publicKey.pem', 'wb') as f:
            f.write(pubKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as f:
            f.write(privKey.save_pkcs1('PEM'))

    def loadKeys(self):
        with open('keys/publicKey.pem', 'rb') as f:
            pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open('keys/privateKey.pem', 'rb') as f:
            privKey = rsa.PrivateKey.load_pkcs1(f.read())

        return pubKey, privKey