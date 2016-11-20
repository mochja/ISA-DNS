import threading
import traceback
import socketserver
import struct
import time
import sys
import http.client
import json

QTYPES = {1:'A', 15: 'MX', 6: 'SOA'}

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

def ip2bytes(ip):
    return struct.pack('!BBBB', *map(int, ip.split('.')))

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
        
def resolve_remote(query):
    domainName, type, klass = query
    
    if type not in [1, 15, 6]:
        return []
    
    h1 = http.client.HTTPSConnection('dns.google.com')
    
    h1.request('GET', '/resolve?name={}&type={}'.format(domainName, type))
    
    r1 = h1.getresponse()
    data = json.loads(r1.read().decode('utf-8'))
    
    if data['Status'] is not 0:
        raise Exception("Invalid Status")
    
    answers = []
    if 'Answer' in data:
        for answer in data['Answer']:
            a = (answer['name'], answer['type'], klass, answer['TTL'], answer['data'])
            answers.append(a)
    
    authority = []
    if 'Authority' in data:
        for answer in data['Authority']:
            a = (answer['name'], answer['type'], klass, answer['TTL'], answer['data'])
            authority.append(a)
        
    return (answers, authority)

def build_answer_data(answer):
    dn, type, cl, ttl, data = answer
    
    if type == 1:
        print('r: {}, type: {}, class IN, addr'.format(dn, 'A', data))
        return txt2domainname(dn) + struct.pack('!HHIH', type, cl, ttl, 4) + ip2bytes(data)

    if type == 15:
        priority, addr = data.split(' ', 2)
        print('r: {}, type: {}, class IN, preference {}, mx {}'.format(dn, 'MX', priority, addr))
        addr = txt2domainname(addr)
        return txt2domainname(dn) + struct.pack('!HHIHH', type, cl, ttl, len(addr) + 2, int(priority)) + addr
    
    if type == 6:
        ns, hostmasta, serialNo, refresh, retry, expire, minTTL = data.split(' ')
        print('r: {}, type: {}, class IN, mname {}'.format(dn, 'SOA', ns))
        soa = txt2domainname(ns) + txt2domainname(hostmasta) + struct.pack('!IIIII', *map(int, [serialNo, refresh, retry, expire, minTTL]))
        return txt2domainname(dn) + struct.pack('!HHIH', type, cl, ttl, len(soa)) + soa
                
            

def dns_response(request):
    
    flags = 0
    flags |= 1 << 15 # set QR to (1) - Response
    flags |= 1 << 8  # recursive flag
    flags |= 1 << 7  # recursive flag
    
    id = struct.pack('!H', request.id)
    flags = struct.pack('!H', flags)
    qdcount = struct.pack('!H', 0)                       # 0 question
    answer = b''
    nswer = b''
    
    ancount = 0
    nscount = 0
    for q in request.queries:
        (dn, type, cl) = q
        print('q: {}, type: {}, class IN'.format(dn, QTYPES[type]))
        
        normal, authoritative = resolve_remote(q)
        
        for r in normal:
            ancount += 1
            answer += build_answer_data(r)
        
        for r in authoritative:
            nscount += 1
            nswer += build_answer_data(r)
    
    ancount = struct.pack('!H', ancount)    # answers
    nscount = struct.pack('!H', nscount)          # 0 authority
    arcount = struct.pack('!H', 0)

    return id + flags + qdcount + ancount + nscount + arcount + \
        answer + nswer

def parse_dns_record(rawdata, offset):
        dn, offset = get_domainname(rawdata, offset)
        dn = pdomainname(dn)
        query_type, query_class = struct.unpack_from('!HH', rawdata, offset=offset)
        offset += 10
        query = dn, query_type, query_class
        
        return (offset, query)
