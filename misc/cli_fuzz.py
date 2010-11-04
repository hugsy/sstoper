#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ptit fuzzer pour tester le server sstp windows
# permet aussi de fingerprint des services sstp
#

from socket import socket, getaddrinfo, AF_UNSPEC, SOCK_STREAM, error as SOCKError
from ssl import wrap_socket, PROTOCOL_TLSv1, CERT_NONE, SSLError
from os import getuid
from sys import path, argv
path.append("/home/chris/code/bordel/")
from random import randint
from utils import INFO, ERR, OK

def get_fuzzy(max_len):
    return "".join([ chr(randint(0, 255)) for x in xrange(randint(0, max_len)) ])

if len(argv) > 1:
    HOST = argv[1]
else :
    HOST = "vpn.tweety.looney"
    
PORT = 443
# neg = """
# {0} {1} HTTP/1.1\r
# Host: {2}\r
# SSTPCORRELATIONID: {3}\r
# Content-Length: {4}\r
# {5}\r
# """.format("SSTP_DUPLEX_POST",
           # "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/",
           # HOST,
           # "1",
           # "1",
           # ""
           # )
neg = """
SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r
Host: %s\r
SSTPCORRELATIONID: {62DFA5C0-E2E0-FD50-D286B00}\r
Content-Length: 18446744073709551615\r
\r
""" % HOST

sock = ssl_sock = None

for ll in getaddrinfo(HOST, PORT, AF_UNSPEC, SOCK_STREAM):
    (family, socktype, proto, canonname, sockaddr) = ll
    
    try:
        sock = socket(family, socktype, proto)
        sock.connect(sockaddr)
        ssl_sock = wrap_socket(sock)
        
    except SOCKError, se:
        if sock : sock.close()
        sock = None
        ERR (se)
        continue

    except SSLError, se:
        sock = None
        ERR (se)
        continue

    break

if ssl_sock is None:
    ERR("Failed to create socket")
    exit(1)

try :    
    INFO ("Sending %d bytes" % len(neg))
    ssl_sock.write(neg)
    data = ssl_sock.read()
    INFO ("Received %d bytes" % len(data))
    
    if "HTTP/1.1 200" in data:
        OK("SSTP service present")
    else :
        INFO("No SSTP service detected")

except KeyboardInterrupt, ki:
    INFO("Leaving")

finally:
    if ssl_sock:
        ssl_sock.close()
        
