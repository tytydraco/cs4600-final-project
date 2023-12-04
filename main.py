# Tyler Nijmeh
# Jack <?????>
# CS4600.02
# Final project

import comms
from Crypto.PublicKey import RSA


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


sender = Person()
receiver = Person()
sender.assign_other(receiver)
receiver.assign_other(sender)
