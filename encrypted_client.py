# Importing necessary modules
import rsa
from cryptography.fernet import Fernet
import socket

# Creating an encrypted_client class
class encrypted_client:
    def __init__(self, ip, port):
        # Initializing the IP and port for the client
        self.ip = ip
        self.port = port
        # Creating a socket object for the client
        self.soc = socket.socket()

    # Method to run the server
    def run_server(self, first_connection=True):
        # Connecting to the specified IP and port
        self.soc.connect((self.ip, self.port))

        if first_connection:
            # Generating RSA keys for the first connection and loading them
            self.generate_keys()
            self.pubKey, self.privKey = self.loadKeys()

            # Receiving the server's public key and sending the client's public key
            self.server_pubKey = rsa.PublicKey.load_pkcs1(self.soc.recv(1024))
            self.soc.send(self.pubKey.save_pkcs1('PEM'))

            # Decrypting the symmetric key using the client's private key
            self.symKey = rsa.decrypt(self.soc.recv(1024), self.privKey)

            # Saving the symmetric key to a file
            with open('keys/symKey.pem', 'wb') as f:
                f.write(self.symKey)

        else:
            # Loading the symmetric key from a file
            with open('keys/symKey.pem', 'rb') as f:
                self.symKey = f.read()

        # Creating a Fernet object for encoding and decoding
        self.encoder = Fernet(self.symKey)
        
    # Method to send messages
    def send(self, text, isBytes=False):
        if not isBytes:
            # Converting the text to bytes if it isn't already
            text = bytes(text, encoding='utf-8')
        # Encrypting the text using the symmetric key
        enc_text = self.encoder.encrypt(text)
        # Sending the encrypted text
        self.soc.send(enc_text)
    
    # Method to receive messages
    def recieve(self, size=1024, isBytes=False):
        # Receiving the encrypted text
        enc_received = self.soc.recv(size)   
        try:
            # Decrypting the text using the symmetric key
            data = self.encoder.decrypt(enc_received)
            if isBytes:
                return data
            # Converting the text from bytes to string
            return data.decode()
        except:
            if enc_received == b'':
                # Raising a TimeoutError if the connection times out
                raise TimeoutError
            # Returning None if the message couldn't be decrypted
            return None
        
    # Method to generate RSA keys and save them to files
    def generate_keys(self):
        (pubKey, privKey) = rsa.newkeys(1024) 
        with open('keys/publicKey.pem', 'wb') as f:
            f.write(pubKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as f:
            f.write(privKey.save_pkcs1('PEM'))

    # Method to load RSA keys from files
    def loadKeys(self):
        with open('keys/publicKey.pem', 'rb') as f:
            pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open('keys/privateKey.pem', 'rb') as f:
            privKey = rsa.PrivateKey.load_pkcs1(f.read())

        return pubKey, privKey