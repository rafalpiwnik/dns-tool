from enum import Enum


# Resource record TYPES as per RFC1035 + some others
class Type(Enum):
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AAAA = 28


TYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "MD": 3,
    "MF": 4,
    "CNAME": 5,
    "SOA": 6,
    "MB": 7,
    "MR": 9,
    "NULL": 10,
    "WKS": 11,
    "PTR": 12,
    "HINFO": 13,
    "MINFO": 14,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
    "DNSKEY": 48,
    "DS": 43,
    "SRV": 33,
    "TLSA": 52,
    "TSIG": 250
}


#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def build_header(num_questions: int = 0):
    ID = 1440

    QR = 1  # 1bit
    OPCODE = 0  # 4bit
    AA = 0  # 1bit
    TC = 0  # 1bit
    RD = 0  # 1bit
    RA = 0  # 1bit
    Z = 0  # 3bit
    RCODE = 0  # 4bit

    QDCOUNT = num_questions
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    params = f"{QR}{str(OPCODE).zfill(4)}{AA}{TC}{RD}{RA}{str(Z).zfill(3)}{str(RCODE).zfill(4)}"
    header = f"{ID:04x}{params}{QDCOUNT:04x}{ANCOUNT:04x}{NSCOUNT:04x}{ARCOUNT:04x}"

    return header


#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def build_question(name: str, QTYPE: Type):
    """name - e.g. cs.berkeley.edu"""
    QNAME = ""
    labels = name.split(".")
    for label in labels:
        length = len(label)
        QNAME += f"{length:02x}"
