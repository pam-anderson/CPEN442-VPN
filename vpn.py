from decimal import Decimal
import socket
import random

# DEFAULTS FOR TESTING    
ip = '127.0.0.1'
port = 5007

# DIFFIE-HELLMAN 2048-bit
dh_2048_p = Decimal(0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D70C354E4ABC9804F1746C08CA18217C32905E462E36CE3B39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9E2BCBF6955817183995497CEA956AE515D2261898FA05105728E5A8AACAA68FFFFFFFFFFFFFFFF)
dh_2048_g = 2
dh_private_key = 0
dh_compute_shared = 0
dh_shared_secret = 0

def computeDHShared():
    global dh_compute_shared
    dh_compute_shared = Decimal(pow(int(dh_2048_g), int(dh_private_key), int(dh_2048_p)))
    print "Send over public channel: " + str(int(dh_compute_shared))

def getDHSharedSecret(shared):
    global dh_shared_secret
    dh_shared_secret = Decimal(pow(int(shared), int(dh_private_key), int(dh_2048_p)))
    print "Shared secret: " + str(int(dh_shared_secret))
    
def getPrivateKey():
    global dh_private_key
    dh_private_key = '%030x' % random.randrange(16**30)
    dh_private_key = long('0x' + dh_private_key, 16)
    print "Private key: " + hex(dh_private_key)
    dh_private_key = Decimal(dh_private_key)

def server():
    getPrivateKey()
    computeDHShared()
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
        getDHSharedSecret(Decimal(data))
        conn.send(str(dh_compute_shared)) # echo    
    conn.close()

def client():
    getPrivateKey()
    computeDHShared()
    buffer_size = 1024
    msg = "Hello, World."
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(str(dh_compute_shared))
    data = s.recv(buffer_size)
    getDHSharedSecret(Decimal(data))
    s.close()
    print "received data: ", data
    

def main():
    server()

if __name__ == "__main__":
    main()

