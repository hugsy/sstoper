#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ptit fuzzer pour tester sstoper
#

from socket import socket, getaddrinfo, AF_UNSPEC, SOCK_STREAM, error as SOCK_ERR
from ssl import wrap_socket, PROTOCOL_TLSv1, CERT_NONE
from os import getuid
from sys import path
path.append("/home/chris/code/bordel/")
from random import randint
from utils import INFO, ERR, OK

if getuid():
    print ("Must be root to bind 443")
    exit(1)
    
sock = None
buflen = 2048
KEY = "server-key.pem"
CRT = "server.pem"

def get_fuzzy(max_len):
    return "".join([ chr(randint(0, 255)) for x in xrange(randint(0, max_len)) ])


for ll in getaddrinfo(None, 443, AF_UNSPEC, SOCK_STREAM, 0):

    (family, socktype, proto, canonname, sockaddr) = ll
    
    try:
        sock = socket(family, socktype, proto)
        sock.bind(sockaddr)
        sock.listen(1)
        
    except SOCK_ERR:
        if sock : sock.close()
        sock = None
        continue
    
    break

if sock is None:
    ERR ("Failed to get socket")
    exit(1)
   
OK ("Listening ... ")

conn = addr = None

try :
    conn, addr = sock.accept()
    INFO ("Connection from %s:%d" % addr[:2])

    ssl_sock = wrap_socket(conn, keyfile=KEY, certfile=CRT, server_side=True)        
    while True:
        data = ssl_sock.read(buflen)

        if not data:
            break
        else :
            INFO ("Received : %s" % data)

        fuzz = get_fuzzy(randint(0, 2**16))
        INFO("Sending %d fuzz bytes" % len(fuzz))
        ssl_sock.write( fuzz )
        
except KeyboardInterrupt, ki:
    INFO("Leaving")

finally:
    if conn:
        conn.close()

exit(0)
