# Tyler Nijmeh
# Jack <?????>
# CS4600.02
# Final project

import comms
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64


class Person:
    # A person owns an RSA key pair.
    pub_key = None
    priv_key = None

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
        with open(filename, 'rb') as f:
            message = f.read()

        aes_key = get_random_bytes(16)
        aes = AES.new(aes_key, AES.MODE_EAX)
        enc_message = aes.encrypt(message)
        rsa = PKCS1_OAEP.new(self.pub_key)
        enc_aes_key = rsa.encrypt(aes_key)

        comms.send(enc_message)
        # comms.send(enc_aes_key)

    def decrypt(self):
        # TODO: do a comms.read() to get the enc message and dec it
        print()


sender = Person()
receiver = Person()
sender.assign_other(receiver)
receiver.assign_other(sender)

sender.send_file('input.txt')
