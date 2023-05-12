# Importing necessary modules
import rsa
from cryptography.fernet import Fernet
import socket

class encrypted_server:
    def __init__(self,port):
        # Initialize a socket object and bind it to the given port
        self.server_socket=socket.socket()
        self.server_socket.bind(('0.0.0.0',port))
        # Listen for incoming connections
        self.server_socket.listen(2)

    def start_server(self,first_connection=True):
        # Accept an incoming connection and store the client socket object and address
        self.client,self.addr=self.server_socket.accept()
        
        if first_connection:
            # Generate new RSA and symmetric keys, save the public and private RSA keys to files
            self.generate_keys()
            # Load the RSA public key of the controller and exchange public RSA keys
            self.pubKey,self.privKey,self.symKey=self.loadKeys()
            self.client.send(self.pubKey.save_pkcs1('PEM'))
            self.controller_pubKey=rsa.PublicKey.load_pkcs1(self.client.recv(1024))
            # Encrypt the symmetric key using the controller's RSA public key and send it to the controller
            self.client.send(rsa.encrypt(self.symKey,self.controller_pubKey))
        else:
            # Load the previously generated symmetric key
            self.symKey=self.loadKeys()[2]

        # Create a Fernet cipher object using the symmetric key
        self.encoder=Fernet(self.symKey)
        
    def send(self,text,isBytes=False):
        # Convert the text to bytes if it is not already in bytes format
        if not isBytes:
            text=bytes(text,encoding='utf-8')
        # Encrypt the text using the Fernet cipher and send it to the client
        enc_text=self.encoder.encrypt(text)
        self.client.send(enc_text)
    
    def recieve(self,size=1024,isBytes=False):
        # Receive the encrypted text from the client
        enc_recieved=self.client.recv(size)
        # If there is no received data, return None
        if not enc_recieved:
            return None
        try:
            # Decrypt the received data using the Fernet cipher
            data=self.encoder.decrypt(enc_recieved)
        except:
            # If there is an error decrypting the data, return None
            return None
        # If isBytes is True, return the data as bytes, otherwise decode the bytes to string and return it
        if isBytes:
            return data
        return data.decode()

    def generate_keys(self):
        # Generate new RSA and symmetric keys, save the public and private RSA keys to files
        (pubKey,privKey)=rsa.newkeys(1024) 
        with open('keys/publicKey.pem', 'wb') as f:
            f.write(pubKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as f:
            f.write(privKey.save_pkcs1('PEM'))
        symKey=Fernet.generate_key()
        with open('keys/symKey.pem','wb') as f:
            f.write(symKey)

    def loadKeys(self):
        # Load the previously generated RSA and symmetric keys from files
        with open('keys/publicKey.pem', 'rb') as f:
            pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open('keys/privateKey.pem', 'rb') as f:
            privKey = rsa.PrivateKey.load_pkcs1(f.read())
        with open('keys/symkey.pem', 'rb') as f:
            symKey=f.read()

        return pubKey, privKey, symKey