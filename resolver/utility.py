import binascii


def to_qname(domain_name: str):
    qname = ""
    domain_name = domain_name.rstrip(".")  # Remove trailing '.'

    labels = domain_name.split(".")
    for label in labels:
        address_hex = binascii.hexlify(label.encode()).decode()
        qname += f"{len(label):02x}{address_hex}"

    if not (len(labels) == 1 and labels[0] == ""):  # Fixes query for "" root
        qname += "00"

    return qname


def fqdn(domain_name: str):
    """Creates fully qualified domain name"""
    return f"{domain_name}."
