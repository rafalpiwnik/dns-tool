from resolver import recursive_lookup

if __name__ == "__main__":
    resp = recursive_lookup("pwr.edu.pl", "AAAA")
    print("\n\n\n")
    resp.print_concise_info()
