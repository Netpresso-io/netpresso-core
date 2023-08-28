import sys

import scapy.config
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IP
from IPython.display import display
import socket
from datetime import datetime

# Open the pcap file
file_name = r'bigFlows.pcap'
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


def extract_pcap(file_name):
    pkts = rdpcap(file_name)
    return pkts


def get_top_dns_old(file_name):
    pkts = extract_pcap(file_name)

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


def get_top_dns(packet_list):
    dns_count = Counter()
    for pkt in packet_list:
        if DNS in pkt.layers() and pkt[DNS].an is not None:
            for dns in pkt[DNS].an:
                if dns.type == 1 or dns.type == 28 \
                        and pkt[DNS].getlayer("DNSQR") is not None:
                    domain_name = pkt[DNS].getlayer("DNSQR").qname.decode('utf-8')
                    dns_count[domain_name] += 1
    return dns_count.most_common(5)


def get_endpoints(packet_list):
    endpoints = set()
    network_address = None
    subnet_mask = None

    for pkt in packet_list:
        if IP in pkt:
            if not network_address or not subnet_mask:
                # Extract network address and subnet mask from the first IP packet
                network_address = (
                        struct.unpack("!I", socket.inet_aton(pkt[IP].src))[0] &
                        struct.unpack("!I", socket.inet_aton(pkt[IP].dst))[0]
                )
                subnet_mask = pkt[IP].dst
                # Convert subnet mask to binary string and count the number of '1' bits
                # subnet_bits = bin(struct.unpack("!I", socket.inet_aton(subnet_mask))[0]).count('1')
            src_addr = struct.unpack("!I", socket.inet_aton(pkt[IP].src))[0]
            dst_addr = struct.unpack("!I", socket.inet_aton(pkt[IP].dst))[0]
            if (src_addr & struct.unpack("!I", socket.inet_aton(subnet_mask))[0]) == network_address:
                # Only add IP addresses that belong to the network
                endpoints.add(pkt[IP].src)
            if (dst_addr & struct.unpack("!I", socket.inet_aton(subnet_mask))[0]) == network_address:
                # Only add IP addresses that belong to the network
                endpoints.add(pkt[IP].dst)

    return list(endpoints)


def calculate_bandwidth_usage(packet_list, endpoints):
    endpoint_usage = {}

    # Initialize endpoint_usage dictionary
    for endpoint in endpoints:
        endpoint_usage[endpoint] = {'upload': 0, 'download': 0, 'last_timestamp': None, "first_timestamp": None}

    # Calculate upload and download usage for each endpoint
    for pkt in packet_list:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if src_ip in endpoints:
                pkt_size = len(pkt)
                timestamp = pkt.time
                if endpoint_usage[src_ip]['last_timestamp'] is not None:
                    endpoint_usage[src_ip]['upload'] += pkt_size * 8
                    endpoint_usage[src_ip]['last_timestamp'] = max(endpoint_usage[src_ip]['last_timestamp'], timestamp)
                else:
                    endpoint_usage[src_ip]['last_timestamp'] = timestamp

                if endpoint_usage[src_ip]['first_timestamp'] is not None:
                    endpoint_usage[src_ip]['upload'] += pkt_size * 8
                    endpoint_usage[src_ip]['first_timestamp'] = min(endpoint_usage[src_ip]['first_timestamp'], timestamp)
                else:
                    endpoint_usage[src_ip]['first_timestamp'] = timestamp

            if dst_ip in endpoints:
                pkt_size = len(pkt)
                timestamp = pkt.time
                if endpoint_usage[dst_ip]['last_timestamp'] is not None:
                    endpoint_usage[dst_ip]['download'] += pkt_size * 8
                    endpoint_usage[dst_ip]['last_timestamp'] = max(endpoint_usage[dst_ip]['last_timestamp'], timestamp)
                else:
                    endpoint_usage[dst_ip]['last_timestamp'] = timestamp

                if endpoint_usage[dst_ip]['first_timestamp'] is not None:
                    endpoint_usage[dst_ip]['download'] += pkt_size * 8
                    endpoint_usage[dst_ip]['first_timestamp'] = min(endpoint_usage[dst_ip]['first_timestamp'], timestamp)
                else:
                    endpoint_usage[dst_ip]['first_timestamp'] = timestamp

    # Calculate upload and download speeds for each endpoint
    for endpoint in endpoint_usage:
        usage = endpoint_usage[endpoint]
        if usage['last_timestamp'] is not None and usage['first_timestamp'] is not None:
            time_diff = float(usage['last_timestamp'] - usage['first_timestamp'])
            upload_speed = usage['upload'] / time_diff / 1024
            download_speed = usage['download'] / time_diff / 1024
            endpoint_usage[endpoint] = {'upload_speed': upload_speed, 'download_speed': download_speed}
        else:
            endpoint_usage[endpoint] = {'upload_speed': 0, 'download_speed': 0}

    return endpoint_usage


packet_list = extract_pcap(file_name)
top_dns = get_top_dns(packet_list)
print("Top 5 DNS (or more if duplicates): ")
print(top_dns)


endpoint_list = get_endpoints(packet_list)
print("Endpoints:\n", endpoint_list)

endpoint_usage = {}
endpoint_usage.update(calculate_bandwidth_usage(packet_list, endpoint_list))
print("Bandwidth usage: ")
for endpoint, data in endpoint_usage.items():
    print(endpoint)
    print('Upload speed:', data['upload_speed'], 'Kbps')
    print('Download speed:', data['download_speed'], 'Kbps')
    print('---')


# print(ndf.nlargest(n=5, columns='Packet count', keep='all'))
# Close the pcap file .nlargest(5, keep='all')
# pkts.close()
# "src": pkt.getlayer(Ether).src,
#             "dst": pkt.getlayer(Ether).dst
