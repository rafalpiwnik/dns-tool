#!/usr/bin/env python
from argparse import ArgumentParser

from resolver import recursive_lookup, lookup

DEFAULT_RECORD_TYPE = "A"
DEFAULT_DNS_SERVER = "1.1.1.1"

parser = ArgumentParser(description="DNS Lookup Tool",
                        usage=f"\tyahoo.com                -> A records for yahoo.com @1.1.1.1\n"
                              f"\tyahoo.com mx             -> MX record types, other params as above\n"
                              f"\tyahoo.com aaaa @8.8.8.8  -> AAAA record types @8.8.8.8\n"
                              f"\t. ns                     -> root name servers\n"
                              f"\tyahoo.com a --norecurse  -> non-recursive query\n"
                              f"\tyahoo.com mx --trace     -> recursive resolve for AAAA")

parser.add_argument("qname", type=str, help="Domain name to be queried")
parser.add_argument("record_type", type=str, nargs="?", default="A", help="Record type e.g. A, AAAA, MX...")
parser.add_argument("dns_server_ip", type=str, nargs="?", default="@1.1.1.1",
                    help="IPv4 address of a DNS server to ask e.g. @8.8.8.8 or @192.168.1.1")
parser.add_argument("--norecurse", action="store_true", help="Queries with recursion_desired = False")
parser.add_argument("-t", "--trace", action="store_true", help="Performs recursive lookup")


def process_request():
    arg = parser.parse_args()

    domain_name: str = arg.qname
    qtype: str = arg.record_type
    dns_ip: str = arg.dns_server_ip
    run_trace: bool = arg.trace
    dont_recurse: bool = arg.norecurse

    if qtype.startswith("@"):
        if dns_ip:
            dns_ip, qtype = qtype, dns_ip
            if qtype.startswith("@"):
                qtype = DEFAULT_RECORD_TYPE

    dns_ip = dns_ip.lstrip("@")

    if run_trace:
        _ = recursive_lookup(domain_name, qtype)
    else:
        _ = lookup(domain_name, qtype, server_ip=dns_ip, recursive=(not dont_recurse))


if __name__ == "__main__":
    process_request()
