from argparse import ArgumentParser

from resolver import recursive_lookup, lookup

parser = ArgumentParser(description="DNS Lookup Tool")
parser.add_argument("name", type=str, help="Domain name to be queried")
parser.add_argument("record_type", type=str, nargs="?", default="A", help="Record type e.g. A, AAAA, MX, etc.")
parser.add_argument("dns_server", type=str, nargs="?", default="1.1.1.1", help="IPv4 address of a DNS server to ask")
parser.add_argument("--norecurse", action="store_true", help="Queries with recursion_desired = False")
parser.add_argument("--trace", action="store_true", help="Performs recursive lookup")

if __name__ == "__main__":
    # res = recursive_lookup("cs.berkeley.edu", "TXT")
    args = parser.parse_args()
    if args.trace:
        resp = recursive_lookup(args.name, args.record_type)
    else:
        resp = lookup(args.name, args.record_type, recursive=(not args.norecurse))
