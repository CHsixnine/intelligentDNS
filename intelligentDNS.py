import socket
from threading import Thread
from scapy.all import *
# import dnslib
from dnslib.server import *

# from dnslib import QTYPE, RR, DNSLabel, dns
# from dnslib.proxy import ProxyResolver as LibProxyResolver
# from dnslib.server import BaseResolver as LibBaseResolver, DNSServer as LibDNSServer
# import datetime
# import sys
# import time
# import threading
# import traceback
# from dnslib import *


class IntelligentDNS():
    def __init__(self):
        self.BUFFER_SIZE = 2 ** 15
        self.DNS_IP = "10.0.0.218"
        self.DNS_PORT = 53
        self.dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_socket.bind((self.DNS_IP, self.DNS_PORT)) 
        
    def run(self):
        t = Thread(target=self.__dns_server__)
        t.start()

    def __dns_server__(self):
        while True:
            data, address = self.dns_socket.recvfrom(self.BUFFER_SIZE)
            data = DNS(data)
            print("-"*50)
            print(data.show())
            answer = DNSRR(rrname=b'www.example.com', ttl=60000, rdlen=4, rdata=b'10.20.1.54')
            data.ancount = 1
            data.qr=1
            data.ancount = 1
            data.an=answer
            self.dns_socket.sendto(bytes(data), address)
            # print(answer[DNS].summary())

# class TestResolver:
#     def resolve(self,request,handler):
#         reply = request.reply()
#         reply.add_answer(*RR.fromZone("www.example.com IN A 10.0.0.218"))
#         return reply    

def main():
    dns_server = IntelligentDNS()
    dns_server.run()

    
    # resolver = TestResolver()
    # logger = DNSLogger(prefix=False)
    # server = DNSServer(resolver,port=53,address="10.0.0.218", logger=logger)
    # server.start_thread()
    # server.start()



if __name__ == '__main__':
    main()