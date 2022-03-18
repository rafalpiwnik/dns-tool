import binascii
from dataclasses import dataclass
from enum import Enum
import numpy as np


# Resource record TYPES as per RFC1035 + some others


class Type(Enum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
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
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


@dataclass
class ByteBuffer:
    buf: bytes
    pos: int = 0

    def skip(self, n: int):
        self.pos += n
        return self

    def read_uint8(self):
        result = int.from_bytes(self.buf[self.pos:self.pos + 1], byteorder="big", signed=False)
        self.pos += 1
        return result

    def read_uint16(self):
        result = int.from_bytes(self.buf[self.pos:self.pos + 2], byteorder="big", signed=False)
        self.pos += 2
        return result

    def peek_uint16(self):
        return int.from_bytes(self.buf[self.pos:self.pos + 2], byteorder="big", signed=False)

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
@dataclass
class DnsHeader:
    ID: int = int("0xaaaa", 16)
    response: bool = False
    recursive: bool = False
    opcode: int = 0
    authoritative_answer: bool = False
    truncation: bool = False
    recursion_desired: bool = True
    recursion_available: bool = True
    Z: int = 0
    response_code: RCode = RCode.NOT_IMPLEMENTED
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def from_buffer(self, bb: ByteBuffer):
        self.ID = bb.read_uint16()
        flags = bb.read_uint16()
        self._parse_flags(flags)
        self.qdcount = bb.read_uint16()
        self.ancount = bb.read_uint16()
        self.nscount = bb.read_uint16()
        self.arcount = bb.read_uint16()
        return self

    def build(self):
        message = f"{self.ID:04x}"

        params = f"{self.response:d}" \
                 f"{bin(self.opcode)[2:].zfill(4)}" \
                 f"{self.authoritative_answer:d}" \
                 f"{self.truncation:d}" \
                 f"{self.recursion_desired:d}" \
                 f"{self.recursion_available:d}" \
                 f"{bin(self.Z)[2:].zfill(3)}" \
                 f"{bin(self.response_code.value)[2:].zfill(4)}"

        message += f"{int(params, 2):04x}"
        message += f"{self.qdcount:04x}{self.ancount:04x}{self.nscount:04x}{self.arcount:04x}"

        return message

    def _parse_flags(self, flags: int):
        # Should change it to bin arithmetic /w flags
        bin_repr = bin(flags)[2:]
        self.response = bool(int(bin_repr[0]))
        self.opcode = int(bin_repr[1:5], 2)
        self.authoritative_answer = bool(int(bin_repr[5]))
        self.truncation = bool(int(bin_repr[6]))
        self.recursion_desired = bool(int(bin_repr[7]))
        self.recursion_available = bool(int(bin_repr[8]))
        self.Z = int(bin_repr[9:12], 2)
        self.response_code = RCode(int(bin_repr[15]))


@dataclass
class DnsQuestion:
    qname: str  # yahoo.com. -> encoded
    qtype: Type  # A
    qclass: np.uint16 = 1  # Class IN


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
