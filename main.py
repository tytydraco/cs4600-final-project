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
    # Generate an RSA keypair with a 2048-bit key.
    priv_key = RSA.generate(2048)
    pub_key = priv_key.public_key()

    # Randomly generate an AES key (16 bytes * 8 bits = 128 bit key)
    aes_key = get_random_bytes(16)

    # And knows the other person's public key.
    other_pub_key = None

    def assign_other(self, other_person):
        # Sets the public key for the other communicator.
        self.other_pub_key = other_person.pub_key

    def send_file(self, filename):
        """
        PROCESS BREAKDOWN:
        1) Encrypt the message (padded to 16-byte block) with our AES key in CBC mode and
           predefined IV. This is our ciphertext.
        2) Encipher the AES key with an RSA cipher (using OAEP (Optimal 
           Asymmetric Encryption Padding)). This links the identity to the AES key.
        3) Hash the ciphertext using the AES key with SHA256. This serves as
           the message authentication code. This will confirm the integrity.

        These pieces are sent to the receiver.
        """

        # Read the message from the file.
        with open(filename, 'rb') as f:
            message = f.read()

        # Pad message to 16-byte block size to make it compatible with AES CBC.
        padded_message = pad(message, AES.block_size)

        # Encrypt the padded message with AES using CBC mode with a shared, predefined IV.
        aes = AES.new(self.aes_key, AES.MODE_CBC, b'1234567890123456')
        enc_message = aes.encrypt(padded_message)

        # Encrypt AES key with the RSA public key.
        rsa = PKCS1_OAEP.new(self.pub_key)
        signature = rsa.encrypt(self.aes_key)

        # Generate SHA256 Hashed-MAC for the message.
        hmac = HMAC.new(self.aes_key, digestmod=SHA256)
        hmac.update(enc_message)

        # Send to virtual sockets.
        comms.send(enc_message, signature, hmac.hexdigest())

    def decrypt(self):
        enc_message, signature, hmac_hexdigest = comms.read()

        # Create RSA cipher using private key.
        rsa = PKCS1_OAEP.new(self.priv_key)

        # Decrypt AES key using RSA private key.
        aes_key = rsa.decrypt(signature)

        # Verify HMAC for integrity.
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(enc_message)
        if hmac_hexdigest != hmac.hexdigest():
            print("Integrity check failed. The message may have been corrupted or tampered with.")
            return

        # Decrypt the message using AES.
        aes = AES.new(aes_key, AES.MODE_CBC, b'1234567890123456')
        decrypted_message = unpad(aes.decrypt(enc_message), AES.block_size)

        # Print the decrypted message.
        print("Decrypted Message:")
        print(decrypted_message.decode('utf-8'))


sender = Person()
receiver = Person()
sender.assign_other(receiver)
receiver.assign_other(sender)

sender.send_file('input.txt')
receiver.decrypt()
