from decimal import Decimal
import socket
import random
import math

# DEFAULTS FOR TESTING    
ip = '127.0.0.1'
port = 5005

# DIFFIE-HELLMAN 2048-bit
dh_2048_p = Decimal(0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D70C354E4ABC9804F1746C08CA18217C32905E462E36CE3B39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9E2BCBF6955817183995497CEA956AE515D2261898FA05105728E5A8AACAA68FFFFFFFFFFFFFFFF)
dh_2048_g = 2
dh_private_key = 0
dh_compute_shared = 0
dh_shared_secret = 0

def server():
    buffer_size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(1)
    
    conn, addr = s.accept()
    print 'Connection address:', addr
    while 1:
        data = conn.recv(buffer_size)
        if not data: break
        print "received data:", data
        getDHSharedSecret(data)
        conn.send(dh_compute_shared) # echo    
    conn.close()

def client():
    buffer_size = 1024
    msg = "Hello, World."

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(dh_compute_shared)
    data = s.recv(buffer_size)
    getDHSharedSecret(data)
    s.close()

    print "received data: ", data

def computeDHShared():
    print "g^x = " + str(math.pow(dh_2048_g, dh_private_key))
    dh_compute_shared = Decimal(Decimal(math.pow(dh_2048_g, dh_private_key)) \
        % Decimal(dh_2048_p))
    print "Send over public channel: " + str(dh_compute_shared)

def getDHSharedSecret(shared):
    dh_shared_secret = Decimal(Decimal(math.pow(shared, dh_compute_shared)) \
        % Decimal(dh_2048_p))
    print "Shared secret: " + str(dh_shared_secret)

def main():
    # generate a random key of 30 hex digits
    dh_private_key = '%030x' % random.randrange(16**30)
    dh_private_key = hex(int('0x' + dh_private_key, 16))
    print "Private key: " + dh_private_key
    computeDHShared()
    server()

if __name__ == "__main__":
    main()

