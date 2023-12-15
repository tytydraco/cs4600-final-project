# Tyler Nijmeh
# Jack Bui
# Kolass rexon 
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
    def __init__(self):
        self.priv_key = RSA.generate(2048)
        self.pub_key = self.priv_key.public_key()
        self.aes_key = get_random_bytes(16)
        self.other_pub_key = None

    def assign_other(self, other_person):
        self.other_pub_key = other_person.pub_key

    def send_file(self, filename):
        """Send an encrypted file to the other person."""
        with open(filename, 'rb') as file_handle:
            message = file_handle.read()

        padded_message = pad(message, AES.block_size)
        enc_message = self._encrypt_message(padded_message)
        signature = self._encrypt_aes_key()
        hmac_digest = self._generate_hmac(enc_message)

        comms.send(enc_message, signature, hmac_digest)

    def _encrypt_message(self, padded_message):
        """Encrypt a padded message using AES CBC mode."""
        aes = AES.new(self.aes_key, AES.MODE_CBC, b'1234567890123456')
        return aes.encrypt(padded_message)

    def _encrypt_aes_key(self):
        """Encrypt the AES key using RSA."""
        rsa = PKCS1_OAEP.new(self.other_pub_key)
        return rsa.encrypt(self.aes_key)

    def _generate_hmac(self, enc_message):
        """Generate HMAC for the encrypted message using SHA256."""
        hmac_gen = HMAC.new(self.aes_key, digestmod=SHA256)
        hmac_gen.update(enc_message)
        return hmac_gen.hexdigest()

    def decrypt(self):
        enc_message, signature, hmac_hexdigest = comms.read()

        rsa = PKCS1_OAEP.new(self.priv_key)

        try:
            aes_key = rsa.decrypt(signature)

            hmac = HMAC.new(aes_key, digestmod=SHA256)
            hmac.update(enc_message)

            if hmac.hexdigest() != hmac_hexdigest:
                raise ValueError("HMAC verification failed.")

            aes = AES.new(aes_key, AES.MODE_CBC, b'1234567890123456')
            padded_message = aes.decrypt(enc_message)
            message = unpad(padded_message, AES.block_size)

            print(message.decode())
        except ValueError as e:
            print("Decryption error:", str(e))


sender = Person()
receiver = Person()
sender.assign_other(receiver)
receiver.assign_other(sender)

sender.send_file('input.txt')
receiver.decrypt()

