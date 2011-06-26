#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ptit fuzzer pour tester le server sstp windows
#

from binascii import hexlify
from socket import socket
from ssl import wrap_socket
from sys import argv
from random import randint
from struct import pack

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

if not "HTTP/1.1 200" in data:
    print("[-] No SSTP service detected")
    ssl_sock.close()
    exit(0)

print ("[+] SSTP service found on %s:%d, starting dumb fuzzing..." % (HOST, PORT))

class SSTP_Packet :
    def __init__(self):
        self.fields = [ ("version", 1, 0),
                        ("reserved_ctrl", 1, 0),
                        ("pktlen", 2, 0) ]

    def fuzz(self, field):
        for name, size, value in self.fields:
            if name == field:
                # print ("Fuzzing field '%s' on %d bits" % (name, size*8))
                value = randint(0, size*8) 
                
    def send(self, sock):
        payload = ""

        for name, size, value in self.fields:
            self.fuzz(name)
            if size == 1:   l = "B"
            elif size == 2: l = "H"
            elif size == 4: l = "I"
            else:
                continue

            payload += pack(">%c" % l, value)

        sock.write(payload)
        # print ("Fuzzed packet sent")

        
class SSTP_Control_Packet(SSTP_Packet):
    def __init__(self):
        SSTP_Packet.__init__(self)
        self.fields += [ ("msg_type", 2, 0),
                         ("num_attr", 2, 0) ]

    def add_attribute(self):
        self.fields += [ ("attr_reserved", 1, 0),
                         ("attr_id", 1, 0),
                         ("attr_size", 2, 0),
                         ("attr_value", 4, 0)]
        
        
try :
    while True:
        sstp = SSTP_Control_Packet()
        sstp.send(ssl_sock)
        
        res = ssl_sock.read()
        if len(res) :
            print hexlify(res)
            
except KeyboardInterrupt, ki:
    print ("Stopping")
except Exception, e:
    print e
    # with("crash.0", "a+") as f:
        # f.write(sstp)
        
exit(0)
