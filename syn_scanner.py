from scapy.layers.inet import ICMP, IP, TCP, sr1
import socket
from datetime import datetime

start = datetime.now()

def icmp_probe(ip):
    icmp_packet = IP(dst=ip) / ICMP()
    resp_packet = sr1(icmp_packet, timeout=10)
    return resp_packet is not None

def syn_scan(ip, ports):
    for port in ports:
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        resp_packet = sr1(syn_packet, timeout=10)
        if resp_packet is not None:
            if resp_packet.getlayer('TCP').flags & 0x12 != 0:
                print(f"{ip}:{port} is open/{resp_packet.sprintf('%TCP.sport%')}")

ends = datetime.now()

if __name__ == "__main__":
    name = input("Hostname / IP Address: ")
    ip = socket.gethostbyname(name)
    ports = [20, 21, 22, 23, 25, 43, 53, 80,
             115, 123, 143, 161, 179, 443, 445,
             514, 515, 993, 995, 1080, 1194,
             1433, 1723, 3128, 3268, 3306, 3389,
             5432, 5060, 5900, 8080, 10000]
    try:
        if icmp_probe(ip):
            syn_ack_packet = syn_scan(ip, ports)
            syn_ack_packet.show()
        else:
            print("Failed to send ICMP packet")
    except AttributeError:
        print("Scan completed!")
        print("<Time:{}>".format(ends - start))