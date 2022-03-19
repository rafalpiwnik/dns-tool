import time

from resolver import lookup

if __name__ == "__main__":
    # yahoo.com
    # m = lookup(".", "NS", recursive=False)
    # m = lookup("a.root-servers.net", "A", recursive=False)
    # m = lookup("yahoo.com", "A", server_ip="198.41.0.4", recursive=False)
    # m = lookup("a.gtld-servers.net", "A", server_ip="198.41.0.4", recursive=False, opt_size=None)
    # m = lookup("yahoo.com", "A", server_ip="192.12.94.30", recursive=False)
    # m = lookup("ns1.yahoo.com", "A", server_ip="192.12.94.30", recursive=False)
    # m = lookup("yahoo.com", "A", server_ip="68.180.131.16", recursive=False)

    m1 = lookup("", "NS", recursive=False)
    root_ns = str(m1.answer[0].rdata)
    m2 = lookup(root_ns, "A", recursive=False)
    root_ns_ip = str(m2.answer[0].rdata)
    m3 = lookup("yahoo.com", "A", server_ip=root_ns_ip, recursive=False)
    com_ns = str(m3.authority[0].rdata)
    m4 = lookup(com_ns, "A", server_ip=root_ns_ip, recursive=False)
    com_ns_ip = str(m4.additional[0].rdata)
    m5 = lookup("yahoo.com", "A", server_ip=com_ns_ip, recursive=False)
    yahoo_ns = str(m5.authority[0].rdata)
    m6 = lookup(yahoo_ns, "A", server_ip=com_ns_ip, recursive=False)
    yahoo_ns_ip = str(m6.authority[0].rdata)
    m7 = lookup("yahoo.com", "A", server_ip=yahoo_ns_ip, recursive=False)
    print("FOUND " + str(m7.answer[0].rdata))

    # header = DnsHeader(qdcount=1)
    # q1 = DnsQuestion(name="cs.berkeley.edu", qtype=QType.A)
    #
    # q2 = DnsQuestion(name=".", qtype=QType.NS, qclass=QClass.IN)
    # q3 = DnsQuestion(name="edu.pl.", qtype=QType.MX, qclass=QClass.IN)
    # q4 = DnsQuestion(name="i-dns.pl", qtype=QType.A, qclass=QClass.IN)
    # q5 = DnsQuestion(name="i-dns.pl", qtype=QType.AAAA, qclass=QClass.IN)
    #
    # pr = DnsResourceRecord().pseudo_record(domain_name=".", udp_payload_size=4096)
    #
    # # Build message
    # message = DnsMessage()
    # message.header = header
    # message.question = [q3]
    #
    # header.arcount = 1
    # message.additional = [pr]
    #
    # built_message = message.build()
    #
    # # CREATE QUERY
    # # RECURSION DESIRED FALSE
    # query1 = create_query(".", "NS")
    # query2 = create_query("a.root-servers.net", "A")
    # query3 = create_query("edu", "NS")  # TO = 198.41.0.4
    # query4 = create_query("b.edu-servers.net", "A")  # TO = 198.41.0.4
    # server_params = ("1.1.1.1", 53)
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # try:
    #     sock.sendto(query3.build(), server_params)
    #     data, _ = sock.recvfrom(4096)
    #     response = DnsMessage().from_bytes(data)
    #     response.print_concise_info()
    # finally:
    #     sock.close()
