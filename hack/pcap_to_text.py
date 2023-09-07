from scapy.all import *
import pandas


# Open the pcap file
pkts = rdpcap(r'test.pcap')

with open("packet_examples.txt", "w", encoding="utf-8") as f:
    for packet in pkts:
        f.write(packet.show(dump=True))


with open("scapy_layers.txt", "w", encoding="utf-8") as f:
    f.write(str(scapy.config.conf.layers))
