import queue

from scapy.all import *
from collections import Counter
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IP
from scapy.layers.l2 import ARP, Ether, srp
import socket
import threading

packet_buff = []
ethernet_interface = "Realtek USB FE Family Controller"  # Ruby needs to make sure this is the interface name
dns_queue = queue.Queue()
bandwidth_queue = queue.Queue()


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


def capture_packets():  # needs to run constantly by thread
    sniff(iface=ethernet_interface, prn=packet_handler)


def packet_handler(packet):
    packet_buff.append((packet, datetime.now().time()))


def get_endpoints_old(packet_list):
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


def get_endpoints():
    res = []
    ip_range = "192.168.0.1/24"  # adjust according to network, '24' stands for 24bit subnet

    # Create an ARP request packet
    arp = ARP(pdst=ip_range)

    # Create an Ethernet frame to encapsulate the ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=False)[0]

    # Process the responses to get endpoint information
    for sent, received in result:
        ip_address = received.psrc
        mac_address = received.hwsrc
        hostname = get_hostname(ip_address)
        res.append((hostname, ip_address, mac_address))

    return res


def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown"


def calculate_bandwidth_usage(packet_list, endpoints):
    endpoint_usage = {}

    # Initialize endpoint_usage dictionary
    for endpoint in endpoints:
        endpoint_usage[endpoint] = {'total_upload': 0, 'total_download': 0, 'upload_time': 0, 'download_time': 0}
    print("endpoint: ", endpoints)
    print("packet list check: " , packet_list)
    # Calculate upload and download usage for each endpoint
    for pkt in packet_list:
        if IP in pkt[0]:
            src_ip = pkt[0][IP].src
            dst_ip = pkt[0][IP].dst

            if src_ip in endpoints:
                pkt_size = len(pkt[0])
                endpoint_usage[src_ip]['upload_time'] += (pkt[1] - pkt[0].time)
                endpoint_usage[src_ip]['total_upload'] += pkt_size * 8

            if dst_ip in endpoints:
                pkt_size = len(pkt[0])
                endpoint_usage[dst_ip]['download_time'] += (pkt[1] - pkt[0].time)
                endpoint_usage[dst_ip]['total_download'] += pkt_size * 8

    # Calculate upload and download speeds for each endpoint
    for endpoint in endpoint_usage:
        usage = endpoint_usage[endpoint]
        total_upload = usage['total_upload']
        total_download = usage['total_download']
        upload_time = usage['upload_time']
        download_time = usage['download_time']

        endpoint_usage[endpoint] = \
            {'upload_speed': total_upload / upload_time / 1024, 'download_speed': total_download / download_time / 1024}

    return endpoint_usage


def thread_function():
    packet_list = []
    packet_list.extend(packet_buff)
    packet_buff.clear()

    top_dns = process_dns_packets(packet_list)
    dns_queue.put(top_dns)

    endpoints = get_endpoints()
    bandwidth_usage = calculate_bandwidth_usage(packet_list, endpoints)
    bandwidth_queue.put(bandwidth_usage)


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


if __name__ == "__main__":
    thread1 = threading.Thread(target=capture_packets)
    thread2 = threading.Thread(target=thread_function)

    thread1.start()
    time.sleep(20)
    thread2.start()

    thread2.join()
    print(dns_queue.get(), bandwidth_queue.get())
