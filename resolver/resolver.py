import binascii
import time
from dataclasses import dataclass, field
from enum import Enum


# Resource record TYPES as per RFC1035 + AAAA
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
        # Would be easier without converting to hex stream, maybe change?
        result = self.buf[self.pos:self.pos + num_bytes].hex()
        self.pos += num_bytes
        return result

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
        self.response_code = RCode(int(bin_repr[15]))

    def __repr__(self):
        return "DNS Header\n" \
               f"\tTransaction ID: 0x{self.ID:04X}\n" \
               f"\tQuestions: {self.qdcount}\n" \
               f"\tAnswer RRs: {self.ancount}\n" \
               f"\tAuthority RRs: {self.nscount}\n" \
               f"\tAdditional RRs: {self.arcount}"


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
        QNAME = ""
        labels = self.name.split(".")
        for label in labels:
            address_hex = binascii.hexlify(label.encode()).decode()
            QNAME += f"{len(label):02x}{address_hex}"
        QNAME += "00"
        message = f"{QNAME}{self.qtype.value:04x}{self.qclass.value:04x}"
        return message


@dataclass
class RData:
    data: str  # Hex stream

    def __repr__(self):
        return self.data


class ARecord(RData):
    def __repr__(self):
        return f"{int(self.data[:2], 16)}.{int(self.data[2:4], 16)}.{int(self.data[4:6], 16)}.{int(self.data[6:], 16)}"


class NSRecord(RData):
    data: str

    def __init__(self, bb: ByteBuffer):
        self.data = bb.read_qname()


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
    qclass: QClass = None
    ttl: int = 0
    rdlength: int = 0  # Length of RDATA in octets
    rdata: RData = RData("")

    def from_buffer(self, bb: ByteBuffer):
        self.name = bb.read_qname()
        self.qtype = QType(bb.read_uint16())
        self.qclass = QClass(bb.read_uint16())
        self.ttl = bb.read_uint32()
        self.rdlength = bb.read_uint16()
        # NOTE
        # RDATA - format varies accoring to qtype, qclass - should be parsed differently
        # e.g. NS -> a-dns.pl but A -> 192.42.39.11
        # Name can be compressed and replaced with pointer

        if self.qtype == QType.A:
            self.rdata = ARecord(bb.read_plain(self.rdlength))
        elif self.qtype == QType.NS:
            self.rdata = NSRecord(bb)
        else:
            # Cannot double read !
            self.rdata = RData(bb.read_plain(self.rdlength))

        return self

    def readable_ttl(self):
        return time.strftime("%H:%M:%S", time.gmtime(self.ttl))

    def __repr__(self):
        result = f"{self.name}:" if len(self.name) > 0 else "<Root>:"
        result += f" type: {self.qtype},"
        result += f" class: {self.qclass}"
        result += f" data: {self.rdata}"
        return result


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
            pass
            # NOTE: Not implemented due to OPT Qtype not having QClass and different layout in general
            # additional_r = DnsResourceRecord().from_buffer(bb)
            # self.additional.append(additional_r)
        bb.pos = 0  # Reset cursor @ buffer
        return self


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


def build_question(name: str, QTYPE: QType = QType.A):
    """name - e.g. cs.berkeley.edu"""
    QNAME = ""
    labels = name.split(".")
    for label in labels:
        address_hex = binascii.hexlify(label.encode()).decode()
        QNAME += f"{len(label):02x}{address_hex}"
    QNAME += "00"

    return QNAME
