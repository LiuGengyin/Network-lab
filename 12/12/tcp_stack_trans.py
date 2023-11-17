import sys
import string
import socket
import time

def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s.bind(('0.0.0.0', int(port)))
    s.listen(3)
    
    cs, addr = s.accept()
    print(addr)

    filename = 'server-output.dat'
    fp = open(filename, 'a')
    
    while True:
        data = cs.recv(1000)
        if data:
            #print(data.decode())
            fp.write(data.decode())
        else:
            break
    print("1")
    fp.close()
    s.close()


def client(ip, port):
    s = socket.socket()
    s.connect((ip, int(port)))

    filename = 'client-input.dat'
    fp = open(filename, 'r')
    
    i = 0
    while True:
        data = fp.read(1000)
        if(data != ''):
            i += s.send(data.encode())
        else:
            break
    
    print(i)
    fp.close()
    s.close()

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2])
    elif sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3])
