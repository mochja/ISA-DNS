"""
Simple DNS Server
"""

import threading
import traceback
import socketserver
import struct
import time
import sys

from helpers import *

PORT=53

class DNSRequest():
    
    def __init__(self, rawdata):
        self.queries = []

        self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack_from('!HHHHHH', rawdata)

        offset = 12

        for i in range(self.qdcount):
            offset, q = parse_dns_record(rawdata, offset)
            self.queries.append(q)

class DNSRequestHandler(socketserver.BaseRequestHandler):
    
    def parse_req(self):
        raise NotImplementedError

    def reply(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            request = self.parse_req()
            self.reply(dns_response(request))
        except Exception:
            traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(DNSRequestHandler):
    
    def parse_req(self):
        data = self.request.recv(4096).strip()
        
        sz = struct.unpack('!H', bytes(data[:2]))
        sz = sz[0]
        
        if sz > 4094:
            raise Exception("packet too big")
        
        return DNSRequest(data[2:sz])

    def reply(self, data):
        sz = struct.pack('!I', int(hex(len(data))[2:].zfill(4), 16))
        return self.request.sendall(sz + data)

class UDPRequestHandler(DNSRequestHandler):

    def parse_req(self):
        return DNSRequest(self.request[0].strip())

    def reply(self, data):
        return self.request[1].sendto(data, self.client_address)

class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer): pass
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer): pass

def main():
    socketserver.TCPServer.allow_reuse_address = True

    servers = [
        ThreadingUDPServer(('', PORT), UDPRequestHandler),
        ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)
        thread.daemon = True
        thread.start()

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
