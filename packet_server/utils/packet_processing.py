import queue
import time

from scapy.all import *
from collections import Counter
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IP
from scapy.layers.l2 import ARP, Ether, srp
import socket
import threading
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi


packet_buff = []

ethernet_interface = "Realtek USB FE Family Controller"  # Ruby needs to make sure this is the interface name

dns_queue = queue.Queue()
bandwidth_queue = queue.Queue()


def process_dns_packets(packet_list):
    dns_count = Counter()
    for pkt in packet_list:
        if DNS in pkt[0].layers() and pkt[0][DNS].an is not None:
            for dns in pkt[0][DNS].an:
                if dns.type == 1 or dns.type == 28 \
                        and pkt[0][DNS].getlayer("DNSQR") is not None:
                    if pkt[0][DNS].getlayer("DNSQR").qname is not None:
                        domain_name = pkt[0][DNS].getlayer("DNSQR").qname.decode('utf-8')
                        dns_count[domain_name] += 1
    return dns_count


def extract_dns_from_packets(packet_list):
    dns_list = []
    for pkt in packet_list:
        if IP in pkt[0]:
            ip_address = pkt[0][IP].dst
            if ip_address == "ruby ip address":
                continue
            try:
                host_info = socket.gethostbyaddr(ip_address)
                print(host_info)
                dns_list.append(host_info)
            except socket.herror as e:
                print(f"Error for IP Address {ip_address}: {e}")

    return dns_list


def extract_pcap(file_name, packet_amount):
    pkts = rdpcap(file_name, packet_amount)
    return pkts


def capture_packets():  # needs to run constantly by thread
    sniff(iface=ethernet_interface, prn=packet_handler)


def packet_handler(packet):
    packet_buff.append((packet, datetime.now().timestamp()))


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
    arp = ARP(op=1, pdst=ip_range)

    # Create an Ethernet frame to encapsulate the ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=False, iface='Realtek USB FE Family Controller')[0]

    # Process the responses to get endpoint information
    for sent, received in result:
        ip_address = received[ARP].psrc
        mac_address = received[ARP].hwsrc
        hostname = get_hostname(ip_address)
        res.append((hostname, ip_address, mac_address))

        # if received.haslayer(ARP):
        #     print("test", received[ARP].psrc)

    print(res)
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

        endpoint_usage[endpoint[1]] = \
            {'total_upload': float(0), 'total_download': float(0), 'upload_time': 0, 'download_time': 0}



    # Calculate upload and download usage for each endpoint
    # print(packet_list)
    for pkt in packet_list:
        if IP in pkt[0]:
            src_ip = pkt[0][IP].src
            dst_ip = pkt[0][IP].dst

            for value in endpoints:
                if src_ip == value[1]:
                    pkt_size = len(pkt[0])
                    endpoint_usage[src_ip]['upload_time'] += (float(pkt[1]) - float(pkt[0].time))
                    endpoint_usage[src_ip]['total_upload'] += float(pkt_size * 8)

            for value in endpoints:
                if dst_ip == value[1]:
                    pkt_size = len(pkt[0])
                    endpoint_usage[dst_ip]['download_time'] += (float(pkt[1]) - float(pkt[0].time))
                    endpoint_usage[dst_ip]['total_download'] += float(pkt_size * 8)

    # print("endpoint_usage : ", endpoint_usage)
    # Calculate upload and download speeds for each endpoint
    for endpoint in endpoint_usage:
        usage = endpoint_usage[endpoint]

        total_upload = usage['total_upload']
        total_download = usage['total_download']
        upload_time = float(usage['upload_time'])
        download_time = float(usage['download_time'])
        # print("total_upload:", total_upload)
        # print("upload time: " ,upload_time)
        # print("total_download:", total_download)
        # print("download_time:", download_time)

        if usage['upload_time'] != 0.0:
            total_upload = usage['total_upload']
            upload_time = (usage['upload_time'])
            endpoint_usage[endpoint] = {'upload_speed': float(total_upload / upload_time / 1024)}

        if usage['download_time'] != 0.0:
            total_download = usage['total_download']
            download_time = (usage['download_time'])
            endpoint_usage[endpoint] = {'download_speed': float(total_download / download_time / 1024)}

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


class DB:
    def __init__(self):
        self.connection_string = "mongodb+srv://user:TY1VocdoRt1Fgoui@cluster0.9x7j3hh.mongodb.net/?retryWrites=true&w=majority"
        self.client = MongoClient(self.connection_string, server_api=ServerApi('1'))
        self.database = self.client["Netpresso"]

    def connect(self):
        try:
            self._client.admin.command('ping')
            print("Pinged your deployment. You successfully connected to MongoDB!")
        except Exception as e:
            print(e)

    def post_bandwidth_usage(self, bandwidth_usage):
        for ip, entry in bandwidth_usage:
            cur_doc = self.database["BandwidthUsage"].find_one({"ip": ip})
            cur_doc_list = list(cur_doc)
            download = entry["download_speed"]
            upload = entry["upload_speed"]
            if len(cur_doc_list) > 0:
                download += cur_doc_list[0]["download"]
                upload += cur_doc_list[0]["upload"]
            self.database["BandwidthUsage"].update_one({"ip":ip},{"$set": {"download": download, "upload": upload}}, upsert=True)

    def post_top_dns(self, dns_list):
        for domain, amount in dns_list:
            cur_doc = self.database["TopDNS"].find_one({"domain": domain})
            cur_doc_list = list(cur_doc)
            if len(cur_doc_list) > 0:
                amount += int(cur_doc_list[0]["amount"])
            self.database["TopDNS"].update_one({"domain":domain},{"$set": {"amount": amount}}, upsert=True)


if __name__ == "__main__":
    db = DB()
    db.connect()

    thread1 = threading.Thread(target=capture_packets)
    # thread2 = threading.Thread(target=thread_function)

    thread1.start()

    time.sleep(5)

    # thread2.start()

    while True:
        packet_list = []
        packet_list.extend(packet_buff)
        packet_buff.clear()

        top_dns = extract_dns_from_packets(packet_list)
        db.post_top_dns(top_dns)

        endpoints = get_endpoints()
        bandwidth_usage = calculate_bandwidth_usage(packet_list, endpoints)
        db.post_bandwidth_usage(bandwidth_usage)

        time.sleep(15)

