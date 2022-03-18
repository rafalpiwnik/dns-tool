import binascii
from dataclasses import dataclass
from enum import Enum
import numpy as np


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


class RCode(Enum):
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    REFUSED = 5


@dataclass
class ByteBuffer:
    buf: bytes
    pos: int = 0

    def read_uint16(self):
        result = self.buf[self.pos:self.pos + 2]
        self.pos += 2
        return result

    def read_qname(self):
        result: list[str] = []
        label_length = self.buf[self.pos]
        while label_length > 0:
            self.pos += 1
            label = self.buf[self.pos:self.pos + label_length].decode()
            result.append(label)
            self.pos += label_length
            label_length = self.buf[self.pos]
        return ".".join(result)


@dataclass
class DnsHeader:
    ID: np.uint16
    recursive: bool
    opcode: np.uint8
    authoritative_answer: bool
    truncation: bool
    recursion_desired: bool
    recursion_available: bool
    Z: bool
    response: RCode
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


@dataclass
class DnsQuestion:
    qname: str  # yahoo.com. -> encoded
    qtype: Type  # A
    qclass: np.uint16 = 1  # Class IN


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

    # Hard to read and debug
    params = f"{QR}{str(OPCODE).zfill(4)}{AA}{TC}{RD}{RA}{str(Z).zfill(3)}{str(RCODE).zfill(4)}"
    header = f"{ID:04x}{int(params, 2):04x}{QDCOUNT:04x}{ANCOUNT:04x}{NSCOUNT:04x}{ARCOUNT:04x}"

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
def build_question(name: str, QTYPE: Type = Type.A):
    """name - e.g. cs.berkeley.edu"""
    QNAME = ""
    labels = name.split(".")
    for label in labels:
        address_hex = binascii.hexlify(label.encode()).decode()
        QNAME += f"{len(label):02x}{address_hex}"
    QNAME += "00"

    return QNAME
