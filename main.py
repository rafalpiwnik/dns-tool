from resolver import recursive_lookup

if __name__ == "__main__":
    # resp = recursive_lookup("www.pwr.edu.pl", "TXT")
    resp = recursive_lookup("www.facebook.com", "MX")
    resp.print_concise_info()
