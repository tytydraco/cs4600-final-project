# Tyler Nijmeh
# Jack Bui
# CS4600.02
# Final project

import comms
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import base64


class Person:
    # A person owns an RSA key pair.
    pub_key = None
    priv_key = None

    # Has an AES key.
    aes_key = get_random_bytes(16)

    # And knows the other person's public key.
    other_pub_key = None

    def __init__(self):
        # Generate an RSA keypair automatically.
        self.priv_key = RSA.generate(2048)
        self.pub_key = self.priv_key.public_key()

    def assign_other(self, other_person):
        # Sets the public key for the other communicator.
        self.other_pub_key = other_person.pub_key

    def send_file(self, filename):
        # Encrypt a message and send RSA and MAC.
        with open(filename, 'rb') as f:
            message = f.read()

        # AES using CBC mode with predefined IV.
        aes = AES.new(self.aes_key, AES.MODE_CBC, b'1234567890123456')

        # Pad message to 16-byte block size.
        padded_message = pad(message, AES.block_size)

        # Encrypt original message with AES.
        enc_message = aes.encrypt(padded_message)

        # Create RSA cipher using public key.
        rsa = PKCS1_OAEP.new(self.other_pub_key)

        # Encrypt AES key with RSA public key for signature.
        signature = rsa.encrypt(self.aes_key)

        # Generate SHA256 Hashed-MAC for the message.
        hmac = HMAC.new(self.aes_key, digestmod=SHA256)
        hmac.update(enc_message)

        # Send to virtual sockets.
        comms.send(enc_message, signature, hmac.hexdigest())

    def decrypt(self):
        # Receive encrypted message, signature, and HMAC.
        enc_message, signature, hmac_hexdigest = comms.read()

        # Create RSA cipher using private key.
        rsa = PKCS1_OAEP.new(self.priv_key)

        try:
            # Decrypt AES key using RSA private key.
            aes_key = rsa.decrypt(signature)

            # Verify HMAC using AES key.
            hmac = HMAC.new(aes_key, digestmod=SHA256)
            hmac.update(enc_message)
            if hmac.hexdigest() != hmac_hexdigest:
                raise ValueError("HMAC verification failed.")

            # AES using CBC mode with predefined IV.
            aes = AES.new(aes_key, AES.MODE_CBC, b'1234567890123456')

            # Decrypt message using AES.
            padded_message = aes.decrypt(enc_message)

            # Unpad message.
            message = unpad(padded_message, AES.block_size)

            # Print decrypted message.
            print(message.decode())
        except ValueError as e:
            print("Decryption error:", str(e))

        


sender = Person()
receiver = Person()
sender.assign_other(receiver)
receiver.assign_other(sender)

sender.send_file('input.txt')
receiver.decrypt()
