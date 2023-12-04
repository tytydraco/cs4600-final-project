# Used to simulate data being sent online,
# but really it's just a text file.

COMMS_MSG_FILE = 'Transmitted_MSG_Data'
COMMS_SIG_FILE = 'Transmitted_SIG_Data'
COMMS_DIG_FILE = 'Transmitted_DIG_Data'


def send(data, sig, digest):
    # Send data to the receiver.
    with open(COMMS_MSG_FILE, 'wb') as f:
        f.write(data)
    with open(COMMS_SIG_FILE, 'wb') as f:
        f.write(sig)
    with open(COMMS_DIG_FILE, 'w') as f:
        f.write(digest)


def read():
    # Read data from the sender.
    with open(COMMS_MSG_FILE, 'rb') as f:
        msg = f.read()
    with open(COMMS_SIG_FILE, 'rb') as f:
        sig = f.read()
    with open(COMMS_DIG_FILE, 'r') as f:
        digest = f.read()

    return msg, sig, digest
