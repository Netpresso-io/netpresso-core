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