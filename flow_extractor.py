import dotenv
import os
dotenv.load_dotenv()

from scapy.utils import RawPcapReader, PcapReader
from scapy.all import *

def extract_flows(pcap_path):
    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            print(pkt.show())

if __name__ == "__main__":
    path = './test_data/test.pcap'
    extract_flows(path)
    