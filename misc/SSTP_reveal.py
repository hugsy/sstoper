#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# 
# SSTP Server revealer: probes target for SSTP specific ressource over HTTP
#   - Christophe Alladoum
#

from socket import socket
from ssl import wrap_socket
from sys import argv
from httplib import HTTPConnection

if len(argv) != 2:
    print("usage: python %s <target_ip_addr>" % argv[0])
    exit(1)
    
HOST = argv[1]
PORT = 443   # SSTP default port
http_neg = """
SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r
Host: %s\r
SSTPCORRELATIONID: {62DFA5C0-E2E0-FD50-D286B00}\r
Content-Length: 18446744073709551615\r
\r
""" % HOST

sock = socket()
sock.connect((HOST, PORT))
ssl_sock = wrap_socket(sock)
active = False

if ssl_sock is None:
    print ("[!] Failed to create socket")
    exit(1)

ssl_sock.write(http_neg)
data = ssl_sock.read()

if "HTTP/1.1 200" in data:
    print("[+] SSTP seams active.")
    active = True
else :
    print("[-] No SSTP service detected")
    
if ssl_sock:
    ssl_sock.close()

if not active :
    exit(0)

print("[+] Trying to download certificate")
i = 0
while True:
    http = HTTPConnection(HOST)
    http.request("GET", "/certsrv/certnew.cer?ReqID=CACert&Renewal=%d&Enc=b64" % i)
    resp = http.getresponse()
    
    if (resp.status != 200):
        break
    else :
        data = resp.read()
        if len(data) and data.startswith("-----BEGIN CERTIFICATE-----"):
            print("[+] Found certificate-%d" % i)
            print ("%s\n" % data)
        elif not data.startswith("-----BEGIN CERTIFICATE-----"):
            break
    i += 1
exit(0)
