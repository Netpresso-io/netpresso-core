from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display


# Open the pcap file
pkts = rdpcap(r'test.pcap')
df = pd.DataFrame()
data_list = []


def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1


pkt: Packet
for pkt in pkts:
    data = {"src": None,
            "dst": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "dns_query": None,
            "dns_id": None,
            "timestamp": pkt.time,
            "protocols": [],
            "payloads": []}
    
    layer: Packet
    for layer in get_packet_layers(pkt):
        layer_name = layer.name
        if layer_name and layer:
            if hasattr(layer, 'qd'):
                if layer_name == "DNS" and hasattr(layer.qd, 'qname'):
                    if layer.qd.qname:
                        data["payloads"].append(layer.qd.qname)
                        print(data["payloads"])
            # data["protocols"].append(layer_name)
            #
            # payload = Packet()
            # payload = layer.show(dump=True)
            # # print(payload)
            # if payload:
            #     data["payloads"].append(payload)
    if data["payloads"]:
        data_list.append(data["payloads"])
    
df = pd.DataFrame(data=data_list)
ndf = df.apply(pd.Series.value_counts)
ndf.columns = ['Packet count']

ndf.plot.bar()
plt.show()

print("Top 5 DNS (or more if duplicates): ")
print(ndf.nlargest(n=5, columns='Packet count', keep='all'))


# Close the pcap file .nlargest(5, keep='all')
# pkts.close()
# "src": pkt.getlayer(Ether).src,
#             "dst": pkt.getlayer(Ether).dst
