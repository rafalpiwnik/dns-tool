from argparse import ArgumentParser

from resolver import recursive_lookup, lookup

parser = ArgumentParser(description="DNS Lookup Tool")
parser.add_argument("name", type=str, help="Domain name to be queried")
parser.add_argument("record_type", type=str, help="Record type e.g. A, AAAA, MX, etc.")
parser.add_argument("--norecurse", action="store_true", help="Queries with recursion_desired = False")
parser.add_argument("--trace", action="store_true", help="Performs recursive lookup")

if __name__ == "__main__":
    res = lookup("facebook.com", "SOA")
    res.print_concise_info()
    # args = parser.parse_args()
    # if args.trace:
    #     resp = recursive_lookup(args.name, args.record_type)
    # else:
    #     resp = lookup(args.name, args.record_type, recursive=(not args.norecurse))
    # print(resp.print_concise_info())
