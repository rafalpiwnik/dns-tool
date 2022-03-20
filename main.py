from resolver import recursive_lookup, lookup

if __name__ == "__main__":
    # resp = recursive_lookup("www.pwr.edu.pl", "TXT")
    # resp = recursive_lookup("www.facebook.com", "MX")
    # resp = lookup("www.facebook.com", "A")
    resp = lookup("www.cs.berkeley.edu", "A")
    resp.print_concise_info()
