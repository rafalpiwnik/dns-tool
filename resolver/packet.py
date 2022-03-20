import binascii
import ipaddress

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum

from typing import Union, Literal
from resolver.buffer import ByteBuffer
from resolver.utility import to_qname, fqdn


class QType(Enum):
    UNKNOWN = 0
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
    recursion_available: bool = False
    Z: int = 0b010  # AD bit set
    response_code: RCode = RCode.NO_ERROR
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

    def concise_info(self, name_pad=25, type_just=10) -> str:
        name_just = max(name_pad, len(self.name) + type_just)
        return fqdn(self.name).ljust(name_just) + self.qclass.name + self.qtype.name.rjust(type_just)

    def __repr__(self):
        return f"{fqdn(self.name)}: type: {self.qtype}, class: {self.qclass}"

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
        """Returns plain hex string representation of RDATA"""
        return self.data

    def __str__(self):
        """Returns parsed RDATA. Subclasses are free to implement whatever parsing they wish
        If no parsing mechanism is provided children fall back to parent implementation of __str__"""
        return self.data


class OPTRecord(RData):
    """OPT pseudo record - no specialized parsing implementing due to brevity"""
    pass


class ARecord(RData):
    def __str__(self):
        addr = ipaddress.ip_address(
            f"{int(self.data[:2], 16)}.{int(self.data[2:4], 16)}.{int(self.data[4:6], 16)}.{int(self.data[6:], 16)}")
        return str(addr)


class AAAARecord(RData):
    def __str__(self):
        raw_addr = ":".join((self.data[i:i + 4]) for i in range(0, len(self.data), 4))
        addr = ipaddress.ip_address(raw_addr)
        return str(addr)


class NSRecord(RData):
    name: str = "INVALID"

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        """NS record is initialized by byte buffer as it has to read name which may have been compressed"""
        self.data = bb.peek_plain(num_bytes)
        self.name = bb.read_qname()

    def __str__(self):
        return self.name


class MXRecord(RData):
    mx_preference: int = 0
    name: str = "INVALID"

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        self.data = bb.peek_plain(num_bytes)
        self.mx_preference = bb.read_uint16()
        self.name = bb.read_qname()

    def __str__(self):
        return self.name


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
    qclass: Union[QClass, int] = None  # Can be either QClass instance or UDP payload size when using OP pseudo-RR
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
        elif self.qtype == QType.NS:
            self.rdata = NSRecord(bb, num_bytes=self.rdlength)
        elif self.qtype == QType.MX:
            self.rdata = MXRecord(bb, num_bytes=self.rdlength)
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
            additional_r = DnsResourceRecord().from_buffer(bb)
            self.additional.append(additional_r)
        bb.pos = 0  # Reset cursor @ buffer
        return self

    def from_bytes(self, data: bytes):
        return self.from_buffer(ByteBuffer(data))

    def build(self) -> bytes:
        """Returns a valid DNS datagram encoded as bytes, ready for transmission with UDP
        NOTE name compression scheme as defined in RFC1035 is not implemented"""
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

    def resolved_ns(self, target_section: Literal["answer", "authority"] = "authority"):
        """For queries containing NS records in target_section looks for corresponding additional A type records
        and returns mapping from NS record domain names onto IPv4Addresses"""
        target = self.authority if target_section == "authority" else self.answer
        ns_target = {fqdn(str(ans.rdata)) for ans in target if ans.qtype == QType.NS}
        result = {ar.name: str(ar.rdata) for ar in self.additional if
                  ar.qtype == QType.A and fqdn(ar.name) in ns_target}
        return result

    def authority_ns(self):
        """Returns names of nameservers in authority section of the message"""
        return [str(auth.rdata) for auth in self.authority if auth.qtype == QType.NS]

    def answer_records(self, filter_by_type: QType):
        """Returns readable representation for records in answer section filtered by QType"""
        answer_records = [str(ans.rdata) for ans in self.answer if ans.qtype == filter_by_type]
        return answer_records

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

    def __repr__(self):
        return f"DNS Message: {repr(self.header)}"

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
