import binascii
import ipaddress
import os
import random
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum

# Resource record TYPES as per RFC1035 + AAAA
from typing import Union, Optional


class QType(Enum):
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
    OPT = 41
    RRSIG = 46


class QClass(Enum):
    IN = 1


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

    def peek_uint16(self):
        return int.from_bytes(self.buf[self.pos:self.pos + 2], byteorder="big", signed=False)

    def read_uint16(self):
        result = self.peek_uint16()
        self.pos += 2
        return result

    def peek_uint32(self):
        part = self.buf[self.pos:self.pos + 4]
        return int.from_bytes(part, byteorder="big", signed=False)

    def read_uint32(self):
        result = self.peek_uint32()
        self.pos += 4
        return result

    def read_plain(self, num_bytes: int):
        result = self.peek_plain(num_bytes)
        self.pos += num_bytes
        return result

    def peek_plain(self, num_bytes: int):
        return self.buf[self.pos:self.pos + num_bytes].hex()

    # Jumps implemented but not error safe (loop jumps?)
    def read_qname(self):
        result: list[str] = []
        has_jumped = False
        pos_return = -1

        label_length = self.buf[self.pos]
        while label_length > 0:
            self.pos += 1
            if (label_length & 0xC0) == 0xC0:
                if not has_jumped:
                    pos_return = self.pos + 1
                offset1 = label_length
                offset2 = self.buf[self.pos]
                pos_target = ((offset1 ^ 0xC0) << 8) | offset2
                self.pos = pos_target
                has_jumped = True
            else:
                label = self.buf[self.pos:self.pos + label_length].decode()
                result.append(label)
                self.pos += label_length
            label_length = self.buf[self.pos]

        if has_jumped:
            self.pos = pos_return
        else:
            self.pos += 1

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
        bin_repr = bin(flags)[2:].zfill(16)
        self.response = bool(int(bin_repr[0]))
        self.opcode = int(bin_repr[1:5], 2)
        self.authoritative_answer = bool(int(bin_repr[5]))
        self.truncation = bool(int(bin_repr[6]))
        self.recursion_desired = bool(int(bin_repr[7]))
        self.recursion_available = bool(int(bin_repr[8]))
        self.Z = int(bin_repr[9:12], 2)
        self.response_code = RCode(int(bin_repr[12:], 2))

    def concise_info(self):
        flags_present = f"{'AA ' if self.authoritative_answer else ''}" \
                        f"{'TC ' if self.truncation else ''}" \
                        f"{'RD ' if self.recursion_desired else ''}" \
                        f"{'RA ' if self.recursion_available else ''}"

        return f"<<HEADER>> opcode: {self.opcode}, status: {self.response_code}, id: {self.ID}\n" \
               f"flags: {flags_present}#query: {self.qdcount}, #answer: {self.ancount}, #authority: {self.nscount}," \
               f" #additional: {self.arcount}"

    def __str__(self):
        return "DNS Header\n" \
               f"\tTransaction ID: 0x{self.ID:04X}\n" \
               f"\tQuestions: {self.qdcount}\n" \
               f"\tAnswer RRs: {self.ancount}\n" \
               f"\tAuthority RRs: {self.nscount}\n" \
               f"\tAdditional RRs: {self.arcount}"


def to_qname(domain_name):
    qname = ""
    domain_name = domain_name.rstrip(".")  # Remove trailing '.'

    labels = domain_name.split(".")
    for label in labels:
        address_hex = binascii.hexlify(label.encode()).decode()
        qname += f"{len(label):02x}{address_hex}"

    if not (len(labels) == 1 and labels[0] == ""):  # Fixes query for "" root
        qname += "00"

    return qname


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
@dataclass
class DnsQuestion:
    name: str = "."
    qtype: QType = QType.A
    qclass: QClass = QClass.IN

    def from_buffer(self, bb: ByteBuffer):
        self.name = bb.read_qname()
        self.qtype = QType(bb.read_uint16())
        self.qclass = QClass(bb.read_uint16())
        return self

    def build(self):
        QNAME = to_qname(self.name)
        message = f"{QNAME}{self.qtype.value:04x}{self.qclass.value:04x}"
        return message

    def fqdn(self):
        """Fully qualified domain name"""
        return f"{self.name}."

    def concise_info(self, name_pad=25, type_just=10) -> str:
        name_just = max(name_pad, len(self.fqdn()) + type_just)
        return self.fqdn().ljust(name_pad) + self.qclass.name + self.qtype.name.rjust(type_just)

    def __repr__(self):
        return f"{self.fqdn()}: type: {self.qtype}, class: {self.qclass}"

    def __str__(self):
        return f"\tName: {'.' if self.name == '' else self.name}\n" \
               f"\tType: {self.qtype.name}\n" \
               f"\tClass: {self.qclass.name}\n"


@dataclass
class RData:
    """Base class for storing and interpreting different DNS RRs types
    data MUST hold a hex stream, no other representation is valid"""
    data: str  # Hex stream

    def __repr__(self):
        return self.data

    def __str__(self):
        return self.data


class OPTRecord(RData):
    pass


class ARecord(RData):
    def __str__(self):
        addr = ipaddress.ip_address(
            f"{int(self.data[:2], 16)}.{int(self.data[2:4], 16)}.{int(self.data[4:6], 16)}.{int(self.data[6:], 16)}")
        return str(addr)


class NameRecord(RData):
    """Reads and stores name-like RRs - e.g. NS, MX.
    Maintains data as hex stream representation as it is used for building message back"""
    name: str = "INVALID"

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        self.data = bb.peek_plain(num_bytes)
        self.name = bb.read_qname()

    def __str__(self):
        return self.name


class AAAARecord(RData):
    def __str__(self):
        raw_addr = ":".join((self.data[i:i + 4]) for i in range(0, len(self.data), 4))
        addr = ipaddress.ip_address(raw_addr)
        return str(addr)


# +------------+--------------+------------------------------+
# | Field Name | Field Type   | Description                  |
# +------------+--------------+------------------------------+
# | NAME       | domain name  | MUST be 0 (root domain)      |
# | TYPE       | u_int16_t    | OPT (41)                     |
# | CLASS      | u_int16_t    | requestor's UDP payload size |
# | TTL        | u_int32_t    | extended RCODE and flags     |
# | RDLEN      | u_int16_t    | length of all RDATA          |
# | RDATA      | octet stream | {attribute,value} pairs      |
# +------------+--------------+------------------------------+
#
#                         OPT RR Format


# 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      |
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                   RDLENGTH                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
@dataclass
class DnsResourceRecord:
    name: str = "."
    qtype: QType = None
    qclass: Union[QClass, int] = None  # Can be either class or UDP payload size when using OP pseudo-RR
    ttl: int = 0
    rdlength: int = 0  # Length of RDATA in octets
    rdata: RData = RData("")

    def from_buffer(self, bb: ByteBuffer):
        self.name = bb.read_qname()
        self.qtype = QType(bb.read_uint16())

        # OPT pseudo RR -> QClass parsed as plain int as it represents UDP payload size
        qclass_value = bb.read_uint16()
        if self.qtype == QType.OPT:
            self.qclass = qclass_value
        else:
            self.qclass = QClass(qclass_value)

        self.ttl = bb.read_uint32()
        self.rdlength = bb.read_uint16()

        if self.qtype == QType.A:
            self.rdata = ARecord(bb.read_plain(self.rdlength))
        elif self.qtype in [QType.NS, QType.MX]:
            self.rdata = NameRecord(bb, num_bytes=self.rdlength)
        elif self.qtype == QType.AAAA:
            self.rdata = AAAARecord(bb.read_plain(self.rdlength))
        elif self.qtype == QType.OPT:
            self.rdata = OPTRecord(bb.read_plain(self.rdlength))
        else:
            self.rdata = RData(bb.read_plain(self.rdlength))

        return self

    def build(self):
        qname = to_qname(self.name)
        qclass_value = self.qclass_value()
        return f"{qname}{self.qtype.value:04x}{qclass_value:04x}{self.ttl:08x}{self.rdlength:04x}{self.rdata.data}"

    def pseudo_record(self, domain_name: str, udp_payload_size: int):
        self.name = domain_name
        self.qtype = QType.OPT
        self.qclass = udp_payload_size
        self.ttl = 0
        self.rdlength = 0
        self.rdata = RData(data="")
        return self

    def qclass_value(self):
        return self.qclass.value if isinstance(self.qclass, QClass) else self.qclass

    def qclass_name(self):
        return self.qclass.name if isinstance(self.qclass, QClass) else str(self.qclass)

    def readable_ttl(self):
        return str(timedelta(seconds=self.ttl))

    def concise_info(self, name_pad: int = 20, secondary_just: int = 8) -> str:
        name_just = max(name_pad, len(self.name) + secondary_just)
        return f"{self.name}.".ljust(name_just) + str(self.ttl).rjust(secondary_just) + \
               self.qclass_name().rjust(secondary_just) + self.qtype.name.rjust(secondary_just) + \
               " " * secondary_just + str(self.rdata)

    def __repr__(self):
        result = f"{self.name}:" if len(self.name) > 0 else "<Root>:"
        result += f" type: {self.qtype},"
        result += f" class: {self.qclass}"
        result += f" data: {self.rdata}"
        return result

    def __str__(self):
        return f"\tName: {'.' if self.name == '' else self.name}\n" \
               f"\tType: {self.qtype.name}\n" \
               f"\tClass: {self.qclass_name()}\n" \
               f"\tTime to live: {self.ttl} ({self.readable_ttl()})\n" \
               f"\tData length: {self.rdlength}\n" \
               f"\tData: {self.rdata}\n\n"


# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
@dataclass
class DnsMessage:
    header: DnsHeader = DnsHeader()
    question: list[DnsQuestion] = field(default_factory=list)
    answer: list[DnsResourceRecord] = field(default_factory=list)
    authority: list[DnsResourceRecord] = field(default_factory=list)
    additional: list[DnsResourceRecord] = field(default_factory=list)

    # Throws ValueError when encountered unknown QType
    def from_buffer(self, bb: ByteBuffer):
        self.header = DnsHeader().from_buffer(bb)
        for _ in range(self.header.qdcount):
            q = DnsQuestion().from_buffer(bb)
            self.question.append(q)
        for _ in range(self.header.ancount):
            an = DnsResourceRecord().from_buffer(bb)
            self.answer.append(an)
        for _ in range(self.header.nscount):
            auth_ns = DnsResourceRecord().from_buffer(bb)
            self.authority.append(auth_ns)
        for _ in range(self.header.arcount):
            # NOTE: Not implemented due to OPT Qtype not having QClass and different layout in general
            additional_r = DnsResourceRecord().from_buffer(bb)
            self.additional.append(additional_r)
        bb.pos = 0  # Reset cursor @ buffer
        return self

    def from_bytes(self, data: bytes):
        return self.from_buffer(ByteBuffer(data))

    # NOTE: Build doesn't compress message using name compressions
    def build(self):
        message = self.header.build()
        for q in self.question:
            message += q.build()
        for ans in self.answer:
            message += ans.build()
        for auth in self.authority:
            message += auth.build()
        for ar in self.additional:
            message += ar.build()
        return binascii.unhexlify(message)

    def __repr__(self):
        return f"DNS Message: {repr(self.header)}"

    def print_concise_info(self):
        print(self.header.concise_info())
        print("\n<<QUESTION>>")
        for q in self.question:
            print(q.concise_info())
        print("\n<<ANSWER>>")
        for ans in self.answer:
            print(ans.concise_info())
        print("\n<<AUTHORITY>>")
        for auth in self.authority:
            print(auth.concise_info())
        print("\n<<ADDITIONAL>>")
        for ar in self.additional:
            print(ar.concise_info())

    # NOTE: appending to string stringbuilder?, performance?
    def __str__(self):
        result = str(self.header) + "\n"
        result += "Queries:\n"
        for quest in self.question:
            result += str(quest)
        result += "Answers:\n"
        for ans in self.answer:
            result += str(ans)
        result += "Authority:\n"
        for auth in self.authority:
            result += str(auth)
        result += "Additional RRs:\n"
        for ar in self.additional:
            result += str(ar)
        return result


# RESOLVER
def create_query(domain_name: str, record_type: Union[str, QType], opt_size: Optional[int] = 4096) -> DnsMessage:
    if opt_size < 0:
        raise ValueError(f"opt_size={opt_size} is invalid. Opt payload size must be a positive integer")

    if isinstance(record_type, QType):
        query_type = record_type
    else:
        try:
            query_type = QType[record_type]
        except KeyError:
            query_type = QType.A

    transaction_id = int(binascii.hexlify(random.randbytes(2)), 16)
    additional_count = 1 if opt_size else 0

    header = DnsHeader(ID=transaction_id,
                       recursion_desired=False,
                       qdcount=1,
                       arcount=additional_count)

    question = DnsQuestion(name=domain_name,
                           qtype=query_type,
                           qclass=QClass.IN)

    opt = DnsResourceRecord().pseudo_record(domain_name=".", udp_payload_size=opt_size)

    msg = DnsMessage(header=header,
                     question=[question],
                     additional=[opt])

    return msg
