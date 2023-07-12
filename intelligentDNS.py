import socket
from threading import Thread
from scapy.all import *
import paho.mqtt.subscribe as subscribe

class IntelligentDNS():
    def __init__(self):
        self.BUFFER_SIZE = 2 ** 15
        self.DNS_IP = "10.0.0.218"
        self.DNS_PORT = 53
        self.dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_socket.bind((self.DNS_IP, self.DNS_PORT)) 
        self.UE_address = ["60.60.0.1", "60.60.0.2", "60.60.0.3", "60.60.0.4", "10.0.0.24"]
        self.UE_DNS_MAPPING = {
            "domain": ["www.mec-app.com.", "www.mec-app.com.", "www.mec-app.com.", "www.mec-app.com.", "www.mec-app.com."],
            "dns_record": ["10.20.1.58", "10.20.1.58", "10.20.1.51", "10.20.1.58", "10.20.1.58"],
            "UE" : self.UE_address
        }
        
    def run(self):
        t = Thread(target=self.__dns_server__)
        t.start()
        t1 = Thread(target=self.__mqtt_dns__)
        t1.start()

    def __mqtt_dns__(self):
        msg = subscribe.simple("free5gc/DNS", hostname="10.0.0.218")
        msg = msg.payload.decode('utf-8')
        UE_address = self.UE_DNS_MAPPING["UE"]
        UE_address.append(msg)
        self.UE_DNS_MAPPING["UE"] = UE_address
        print(UE_address)

    def __dns_server__(self):
        while True:
            data, address = self.dns_socket.recvfrom(self.BUFFER_SIZE)
            print(address[0])
            if address[0] in self.UE_DNS_MAPPING["UE"]:
                print(address[0])
            data = DNS(data)

            answer_record = self.__search_record__(domain_name = data.qd.qname.decode('utf-8'), source_ip = address[0])
            print(answer_record)
            answer = DNSRR(rrname=data.qd.qname, ttl=5, rdlen=4, rdata=answer_record)
            data.ancount = 1
            data.qr=1
            data.ancount = 1
            data.an=answer
            self.dns_socket.sendto(bytes(data), address)
   
    def __search_record__(self, source_ip, domain_name):
        print(source_ip, domain_name)
        ue_dns_mapping = {"domain": [], "dns_record": [], "UE": []}
        try:
            for domain in range(len(self.UE_DNS_MAPPING["domain"])):
                if self.UE_DNS_MAPPING["domain"][domain] == domain_name:
                    ue_dns_mapping["domain"].append(self.UE_DNS_MAPPING["domain"][domain])
                    ue_dns_mapping["dns_record"].append(self.UE_DNS_MAPPING["dns_record"][domain])
                    ue_dns_mapping["UE"].append(self.UE_DNS_MAPPING["UE"][domain])
            for ue in range(len(ue_dns_mapping["UE"])):
                if source_ip == ue_dns_mapping["UE"][ue]:
                    return ue_dns_mapping["dns_record"][ue]
            return ue_dns_mapping["dns_record"][0]
        except:
            pass


def main():
    dns_server = IntelligentDNS()
    dns_server.run()

if __name__ == '__main__':
    main()
