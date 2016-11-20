import threading
import traceback
import socketserver
import struct
import time
import sys
import http.client
import json
import uuid

import config

import dns.rdatatype
import dns.rdataclass

args = config.args

QTYPES = {1:'A', 15: 'MX', 6: 'SOA'}
custom_mx = uuid.uuid4().hex

# https://github.com/shuque/pydig GNUv2 (edited)
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

# https://github.com/shuque/pydig GNUv2 (edited)
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

# https://github.com/shuque/pydig GNUv2 (edited)
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
        return (3, [], [])
    
    h1 = http.client.HTTPSConnection('dns.google.com')
    
    h1.request('GET', '/resolve?name={}&type={}'.format(domainName, type))
    
    r1 = h1.getresponse()
    data = json.loads(r1.read().decode('utf-8'))
    
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

    return (int(data['Status']), answers, authority)

def resolve_fake(query, ip):
    domainName, type, klass = query

    answers = []
    
    if type not in [1, 15, 6]:
        return (3, answers, [])

    # sam sebe pan pri ostatnych
    if type == 1:
        a = (domainName, type, klass, 1, str(ip))
        answers.append(a)

    # sam sebe pan pri MX
    if type == 15:
        a = (domainName, type, klass, 1, '10 ' + domainName)
        answers.append(a)

    return (0, answers, [])

def build_answer_data(answer):
    dn, type, cl, ttl, data = answer
    
    if type == 1:
        print('r: {}, type: {}, class {}, addr {}'.format(dn, dns.rdatatype.to_text(type), dns.rdataclass.to_text(cl), data))
        return txt2domainname(dn) + struct.pack('!HHIH', type, cl, ttl, 4) + ip2bytes(data)

    if type == 15:
        priority, addr = data.split(' ', 2)
        
        if not addr.endswith('.'):
            addr += '.'
        
        print('r: {}, type: {}, class {}, preference {}, mx {}'.format(dn, dns.rdatatype.to_text(type), dns.rdataclass.to_text(cl), priority, addr))
        addr = txt2domainname(addr)
        return txt2domainname(dn) + struct.pack('!HHIHH', type, cl, ttl, 2 + len(addr), int(priority)) + addr
    
    if type == 6:
        ns, hostmasta, serialNo, refresh, retry, expire, minTTL = data.split(' ')
        
        if not ns.endswith('.'):
            ns += '.'
        
        if not hostmasta.endswith('.'):
            hostmasta += '.'
        
        print('r: {}, type: {}, class {}, mname {}'.format(dn, dns.rdatatype.to_text(type), dns.rdataclass.to_text(cl), ns))
        soa = txt2domainname(ns) + txt2domainname(hostmasta) + struct.pack('!IIIII', *map(int, [serialNo, refresh, retry, expire, minTTL]))
        return txt2domainname(dn) + struct.pack('!HHIH', type, cl, ttl, len(soa)) + soa
    
    raise Exception('cant create response for that')

def resolve_zones(query, rr):
    dn, type, klass = query
    
    normal = []
    authoritative = []
    
    for r in rr:
        a = (dn, r.rdtype, r.rdclass, rr.ttl, str(r).replace('\\@', '.'))
        
        if r.rdtype == 6:
            authoritative.append(a)
        else:
            normal.append(a)
        
    return (0, normal, authoritative)

def dns_response(request):
    answer = b''
    nswer = b''
    flags = 0
    ancount = 0
    nscount = 0
    
    status = 3 # default status not found
    
    for q in request.queries:
        (dn, type, cl) = q
        print('q: {}, type: {}, class {}'.format(dn, dns.rdatatype.to_text(type), dns.rdataclass.to_text(cl)))
            
        rr = None
        for zone in config.zones:
            try:
                rr = zone.find_rdataset(dn, type)
                break
            except: pass
            
        if rr is not None and args.mitm is None:
            flags |= 1 << 10 # set authoritative
            status, normal, authoritative = resolve_zones(q, rr)
        else:
            status, normal, authoritative = resolve_remote(q) if args.mitm is None or type in [6] else resolve_fake(q, str(args.mitm[0]))
        
        for r in normal:
            ancount += 1
            answer += build_answer_data(r)
        
        for r in authoritative:
            nscount += 1
            nswer += build_answer_data(r)
    
    flags |= 1 << 15 # set QR to (1) - Response
    flags |= 1 << 7 # 
    flags |= 1 << 8 # 
    flags |= status
    
    id = struct.pack('!H', request.id)
    flags = struct.pack('!H', flags)
    qdcount = struct.pack('!H', 0)
    ancount = struct.pack('!H', ancount)
    nscount = struct.pack('!H', nscount)
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
