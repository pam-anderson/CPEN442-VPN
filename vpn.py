from decimal import Decimal
import socket
import random

# DEFAULTS FOR TESTING    
ip = '127.0.0.1'
port = 5007

# DIFFIE-HELLMAN 2048-bit
dh_2048_p = Decimal(0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D70C354E4ABC9804F1746C08CA18217C32905E462E36CE3B39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9E2BCBF6955817183995497CEA956AE515D2261898FA05105728E5A8AACAA68FFFFFFFFFFFFFFFF)
dh_2048_g = 2

# MAC CONSTANTS
mac_size = 64

# KEY FOR MESSAGE ENCRYPTION
dh_private_key = 0 
dh_compute_shared = 0
dh_shared_secret = 0

# KEY FOR MAC
mac_private_key = 0
mac_compute_shared = 0
mac_shared_secret = 0

def computeDHShared(key):
    shared = Decimal(pow(int(dh_2048_g), int(key), int(dh_2048_p)))
    print "\nSend over public channel: " + str(int(shared))
    return shared

def getDHSharedSecret(key, shared):
    secret = Decimal(pow(int(shared), int(key), int(dh_2048_p)))
    print " \nShared secret: " + str(int(secret)) 
    return secret
    
# Generate a random 30 digit long key
def getPrivateKey():
    key = '%030x' % random.randrange(16**30)
    key = long('0x' + key, 16)
    print "\nPrivate key: " + hex(key)
    key = Decimal(key)
    return key

# We need 2 keys - one for the message, the other for the MAC
def establishPrivateKeys():
    global dh_private_key
    dh_private_key = getPrivateKey()
    global mac_private_key
    mac_private_key = getPrivateKey()
    global dh_compute_shared
    dh_compute_shared = computeDHShared(dh_private_key)
    global mac_compute_shared
    mac_compute_shared = computeDHShared(mac_private_key)

def addMAC(msg):
    pass
#    if length(mac_

def server():
    establishPrivateKeys()
    buffer_size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # For Testing
    s.bind((ip, port))

    # User can specify a port number
    #try:
    #    serverport = input("Specify a port number (5007 used if not specified): ")
    #    try:
    #        s.bind((socket.gethostname(), serverport))
    #    # If invalid port number, let user know and exit
    #    except Exception as error:
    #        print "Invalid port number. Exiting..."
    #        exit()
    ## Default port number used
    #except Exception as exception:
    #    s.bind((socket.gethostname(), port))

    print "Server listening..."
    s.listen(1)
    
    # Establish shared keys
    conn, addr = s.accept()
    print '\nConnection address:', addr
    data = conn.recv(buffer_size)
    print "\nReceived shared key 1:", data 
    global dh_shared_secret
    dh_shared_secret = getDHSharedSecret(dh_private_key, Decimal(data))
    conn.send(str(dh_compute_shared))
    data = conn.recv(buffer_size)
    global mac_shared_secret
    mac_shared_secret = getDHSharedSecret(mac_private_key, Decimal(data))
    conn.send(str(mac_compute_shared))

    # Listen for and send messages
    while(True):
        data = s.recv(buffer_size)
        print data

    conn.close()

def client():
    establishPrivateKeys()
    buffer_size = 1024
    msg = "Hello, World."
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # For Testing
    s.connect((ip, port))
    #hostname = raw_input("Enter hostname or IP address: ")

    ## User can specify a port number
    #try:
    #    clientport = input("Specify a port number (5007 used if not specified): ")
    #    try:
    #        s.connect((socket.gethostname(), clientport))
    #    # Could not connect, let user know and exit
    #    except Exception as error:
    #        print "Invalid port number. Exiting..."
    #        exit()
    ## Default port number used
    #except Exception as exception:
    #    s.connect((socket.gethostname(), port))

    # Establish shared keys
    s.send(str(dh_compute_shared))
    data = s.recv(buffer_size)
    global dh_shared_secret
    dh_shared_secret = getDHSharedSecret(dh_private_key, Decimal(data))
    s.send(str(mac_compute_shared))
    data = s.recv(buffer_size)
    global mac_shared_secret
    mac_shared_secret = getDHSharedSecret(mac_private_key, Decimal(data))

    while(True):
        msg = raw_input("Data to be Sent: ")


    s.close()
    print "\nReceived data: ", data

def main():
    server()

if __name__ == "__main__":
    main()

