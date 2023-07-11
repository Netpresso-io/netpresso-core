from scapy.all import *
from collections import Counter
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IP


def process_dns_packets(packet_list):
    dns_count = Counter()
    for pkt in packet_list:
        if DNS in pkt.layers() and pkt[DNS].an is not None:
            for dns in pkt[DNS].an:
                if dns.type == 1 or dns.type == 28 \
                        and pkt[DNS].getlayer("DNSQR") is not None:
                    domain_name = pkt[DNS].getlayer("DNSQR").qname.decode('utf-8')
                    dns_count[domain_name] += 1
    return dns_count.most_common(5)


def extract_pcap(file_name, packet_amount):
    pkts = rdpcap(file_name, packet_amount)
    return pkts


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


class PacketUtils:
    @staticmethod
    def get_top_dns(file_name, packet_amount):
        packet_list = extract_pcap(f'resources/{file_name}', packet_amount)
        top_dns = process_dns_packets(packet_list)
        return top_dns

    @staticmethod
    def get_bandwidth_usage(file_name, packet_amount):
        packet_list = extract_pcap(f'resources/{file_name}', packet_amount)
        endpoints = get_endpoints(packet_list)
        return calculate_bandwidth_usage(packet_list, endpoints)

