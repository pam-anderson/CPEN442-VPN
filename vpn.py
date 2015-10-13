import socket
    
ip = '127.0.0.1'
port = 5005

def server():
    buffer_size = 20
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(1)
    
    conn, addr = s.accept()
    print 'Connection address:', addr
    while 1:
        data = conn.recv(buffer_size)
        if not data: break
        print "received data:", data
        conn.send(data) # echo    
    conn.close()

def client():
    buffer_size = 1024
    msg = "Hello, World."

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(msg)
    data = s.recv(buffer_size)
    s.close()

    print "received data: ", data

def main():
    server()

if __name__ == "__main__":
    main()

