import time
import resolver as rslv
from resolver import lookup
from resolver.packet import QType

if __name__ == "__main__":
    # yahoo.com
    # m = lookup(".", "NS", recursive=False)
    # m = lookup("a.root-servers.net", "A", recursive=False)
    # m = lookup("yahoo.com", "A", server_ip="198.41.0.4", recursive=False)
    # m = lookup("a.gtld-servers.net", "A", server_ip="198.41.0.4", recursive=False, opt_size=None)
    # m = lookup("yahoo.com", "A", server_ip="192.12.94.30", recursive=False)
    # m = lookup("ns1.yahoo.com", "A", server_ip="192.12.94.30", recursive=False)
    # m = lookup("yahoo.com", "A", server_ip="68.180.131.16", recursive=False)

    # DDoS protection on root servers / TLD servers??
    # m = lookup("yahoo.com", "A", server_ip="198.41.0.4", recursive=False)
    m = lookup("yahoo.com", "A", server_ip="192.12.94.30", recursive=False)

    # m1 = lookup("", "NS", recursive=False)
    # root_ns = str(m1.answer[0].rdata)
    # m2 = lookup(root_ns, "A", recursive=False)
    # root_ns_ip = str(m2.answer[0].rdata)
    # m3 = lookup("yahoo.com", "A", server_ip=root_ns_ip, recursive=False)
    # com_ns = str(m3.authority[0].rdata)
    # m4 = lookup(com_ns, "A", server_ip=root_ns_ip, recursive=False)
    # com_ns_ip = str(m4.additional[0].rdata)
    # m5 = lookup("yahoo.com", "A", server_ip=com_ns_ip, recursive=False)
    # yahoo_ns = str(m5.authority[0].rdata)
    # m6 = lookup(yahoo_ns, "A", server_ip=com_ns_ip, recursive=False)
    # yahoo_ns_ip = str(m6.authority[0].rdata)
    # m7 = lookup("yahoo.com", "A", server_ip=yahoo_ns_ip, recursive=False)
    # print("FOUND " + str(m7.answer[0].rdata))

    # rslv.recursive_resolve("yahoo.com")
