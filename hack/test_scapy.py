from scapy.all import *
import pandas

# Open the pcap file
pkts = rdpcap(r'hack\test.pcap')
df = pandas.DataFrame()
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
    data = {"src": pkt.getlayer(Ether).src,
            "dst": pkt.getlayer(Ether).dst,
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
        if layer_name is not None:
            data["protocols"].append(layer_name)
            
            payload = Packet()
            payload = layer.show(dump=True)
            # print(payload)
            if payload:
                data["payloads"].append(payload)

    data_list.append(data)
    
df = pandas.DataFrame(data_list)
print(len(df))

# Close the pcap file
# pkts.close()
