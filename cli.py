"""
Simple DNS Server
"""

import threading
import traceback
import socketserver
import time
import sys

PORT=5053

def dns_response(request):
    pass

class DNSRequestHandler(socketserver.BaseRequestHandler):
    
    def parse_req(self):
        raise NotImplementedError

    def reply(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            request = self.parse_req()
            print(request)
            self.reply(dns_response(request))
        except Exception:
            traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(DNSRequestHandler):
    
    def parse_req(self):
        data = self.request.recv(1024).strip()
        sz = int(data[:2].encode('hex'), 16)

        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")

        return data[2:]

    def reply(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(DNSRequestHandler):

    def parse_req(self):
        return self.request[0].strip()

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
