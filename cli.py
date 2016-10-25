"""
Simple DNS Server
"""

import threading
import traceback
import socketserver
import struct
import time
import sys

PORT=53

def txt2domainname(input, canonical_form=False):
    """turn textual representation of a domain name into its wire format"""
    if input == ".":
        d = b'\x00'
    else:
        d = b""
        for label in input.split('.'):
            label = label.encode('ascii')
            if canonical_form:
                label = label.lower()
            length = len(label)
            d += struct.pack('B', length) + label
    return d


def get_domainname(pkt, offset):
    """decode a domainname at the given packet offset; see RFC 1035"""
    global count_compression
    labellist = []               # a domainname is a sequence of labels
    Done = False
    while not Done:
        llen, = struct.unpack('B', pkt[offset:offset+1])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            count_compression += 1
            c_offset, = struct.unpack('!H', pkt[offset:offset+2])
            c_offset = c_offset & 0x3fff       # last 14 bits
            offset +=2
            rightmostlabels, junk = get_domainname(pkt, c_offset)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = pkt[offset:offset+llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def pdomainname(labels):
    """given a sequence of domainname labels, return a quoted printable text
    representation of the domain name"""

    printables = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-*+'
    result_list = []

    for label in labels:
        result = ''
        for c in label:
            if isinstance(c, int):
                c_int, c_chr = c, chr(c)
            else:
                c_int, c_chr = ord(c), c.decode()
            if c in printables:
                result += c_chr
            else:
                result += ("\\%03d" % c_int)
        result_list.append(result)

    if result_list == ['']:
        return "."
    else:
        return ".".join(result_list)

def dns_response(request):
    
    id = struct.pack('!H', request.id)
    flags = struct.pack('!H', 0)
    qdcount = struct.pack('!H', 0)              # 0 question
    ancount = struct.pack('!H', 1)              # 1 answer
    nscount = struct.pack('!H', 0)              # 0 authority
    arcount = struct.pack('!H', 0)

    answer = b''

    ip = struct.pack('!BBBB', 127, 0, 0, 1)

    for q in request.queries:
        dn, type, cl = q
        ttl = 0
        answer += txt2domainname(dn) + struct.pack('!HHIH', type, cl, ttl, 4) + ip

    return id + flags + qdcount + ancount + nscount + arcount + \
        answer

def parse_dns_record(rawdata, offset):
        dn, offset = get_domainname(rawdata, offset)
        dn = pdomainname(dn)
        query_type, query_class = struct.unpack_from('!HH', rawdata, offset=offset)
        offset += 10
        query = dn, query_type, query_class
        
        return (offset, query)

class DNSRequest():
    
    def __init__(self, rawdata):
        print(rawdata)

        self.queries = []

        self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack_from('!HHHHHH', rawdata)

        print("id: %d flags: %d qdcount: %d, ancount: %d, nscount: %d, arcount: %d" % (
            self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount))
        
        offset = 12

        for i in range(self.qdcount):
            offset, q = parse_dns_record(rawdata, offset)
            print(q)
            self.queries.append(q)
    

class DNSRequestHandler(socketserver.BaseRequestHandler):
    
    def parse_req(self):
        raise NotImplementedError

    def reply(self, data):
        raise NotImplementedError

    def handle(self):
        print("handle packet")
        try:
            request = self.parse_req()
            self.reply(dns_response(request))
        except Exception:
            traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(DNSRequestHandler):
    
    def parse_req(self):
        data = self.request.recv(1024).strip()
        sz = int(data[:2], 16)

        print("packet size %s" % sz)

        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")

        return DNSRequest(data[2:])

    def reply(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(DNSRequestHandler):

    def parse_req(self):
        return DNSRequest(self.request[0].strip())

    def reply(self, data):
        return self.request[1].sendto(data, self.client_address)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer): pass
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer): pass

def main():
    print("Starting nameserver...")

    servers = [
        ThreadingUDPServer(('', PORT), UDPRequestHandler),
        ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)
        thread.daemon = True
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

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
            print("done.")
