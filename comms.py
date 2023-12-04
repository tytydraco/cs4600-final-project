# Used to simulate data being sent online,
# but really it's just a text file.

COMMS_MSG_FILE = 'Transmitted_MSG_Data'
COMMS_SIG_FILE = 'Transmitted_SIG_Data'


def send(data, sig):
    # Send data to the receiver.
    with open(COMMS_MSG_FILE, 'wb') as f:
        f.write(data)
    with open(COMMS_SIG_FILE, 'wb') as f:
        f.write(sig)


def read():
    # Read data from the sender.
    with open(COMMS_MSG_FILE, 'rb') as f:
        msg = f.read()
    with open(COMMS_SIG_FILE, 'rb') as f:
        sig = f.read()

    return msg, sig
