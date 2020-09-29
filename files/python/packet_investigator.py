import sys
from scapy.all import *


class scapy_demo(object):
    def __init__(self):
        super(scapy_demo, self).__init__()
        pass

    def main(self, pcap_file):
        pcap = rdpcap(pcap_file)
        print(pcap.sessions())

    def find_unique_ips(self, pcap_file):
        pcap = rdpcap(pcap_file)
        unique_ips = set()
        for pkt in pcap:
            try:
                unique_ips.add(pkt[IP].src)
                unique_ips.add(pkt[IP].dst)
            except IndexError:
                pass
        print(unique_ips)

    def find_packets_with_ip(self, pcap_file, _ip):
        pcap = rdpcap(pcap_file)
        for pkt in pcap:
            try:
                if pkt[IP].src == _ip or pkt[IP].dst == _ip:
                    print(pkt)
            except IndexError:
                pass

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        sys.exit("Usage: python scapy file.pcap [unique_ips]")
    scapy_parser = scapy_demo()
    if sys.argv.__contains__("-unique_ips"):        
        scapy_parser.find_unique_ips(sys.argv[1])
    if sys.argv.__contains__("-susp_ip"):
        scapy_parser.find_packets_with_ip(sys.argv[1], sys.argv[3])
    else:
        scapy_parser.main(sys.argv[1])

    