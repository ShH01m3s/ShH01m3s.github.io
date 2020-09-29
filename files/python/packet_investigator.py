import sys
from scapy.all import *
from pcapy import open_offline, open_live
from impacket.ImpactDecoder import EthDecoder


class packet_investigator(object):
    def __init__(self):
        super(packet_investigator, self).__init__()
        pass

    def main(self, pcap_file):
        pcap = rdpcap(pcap_file)
        print(pcap.sessions())

    def read_packet(self, hdr, data):
        decoder = EthDecoder()
        ether =  decoder.decode(data)
        ip = ether.child()
        transport = ip.child()
        print(transport)

    def impact_demo(self, pcap_file):
        pcap = open_offline(pcap_file)
        pcap.loop(0, self.read_packet)

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
        sys.exit("Usage:  %s [file].pcap [-unique_ips] [-susp_ip]" % sys.argv[0])
    pckt_investigator = packet_investigator()
    if sys.argv.__contains__("-unique_ips"):        
        pckt_investigator.find_unique_ips(sys.argv[1])
    if sys.argv.__contains__("-susp_ip"):
        pckt_investigator.find_packets_with_ip(sys.argv[1], sys.argv[3])
    if sys.argv.__contains__("impact_demo"):
        pckt_investigator.impact_demo(sys.argv[1])
    else:
        pckt_investigator.main(sys.argv[1])

    