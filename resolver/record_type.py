import ipaddress
from dataclasses import dataclass
from enum import Enum

from resolver.buffer import ByteBuffer


class QType(Enum):
    """
    Supported query QTypes
    If parser encounters unknown RR type it falls back to base RData implementation which encapsulates a plain hex str
    This list can be extended in which case parsing for new types shall be provided by introducing a RData subclass
    and modifying RecordFactory to accommodate a new resource record type
    """
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
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    XRRSET = 7
    NOTAUTH = 8
    NOTZONE = 9


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


class NameRecord(RData):
    name: str = "INVALID"

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        """NS record is initialized by byte buffer as it has to read name which may have been compressed"""
        self.data = bb.peek_plain(num_bytes)
        self.name = bb.read_qname()

    def __str__(self):
        return self.name


class NSRecord(NameRecord):
    pass


class CNAMERecord(NameRecord):
    pass


class SOARecord(RData):
    primary_ns: str = "INVALID"
    responsible_mx: str = "INVALID"
    serial: int = 0
    refresh: int = 0
    retry: int = 0
    expire_limit: int = 0
    minimum_ttl: int = 0

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        self.data = bb.peek_plain(num_bytes)
        self.primary_ns = bb.read_qname()
        self.responsible_mx = bb.read_qname()
        self.serial = bb.read_uint32()
        self.refresh = bb.read_uint32()
        self.retry = bb.read_uint32()
        self.expire_limit = bb.read_uint32()
        self.minimum_ttl = bb.read_uint32()

    def __str__(self):
        return f"{self.primary_ns}.\t{self.responsible_mx}." \
               f" {self.serial} {self.retry} {self.expire_limit} {self.minimum_ttl}"


class MXRecord(RData):
    mx_preference: int = 0
    name: str = "INVALID"

    def __init__(self, bb: ByteBuffer, num_bytes: int):
        self.data = bb.peek_plain(num_bytes)
        self.mx_preference = bb.read_uint16()
        self.name = bb.read_qname()

    def __str__(self):
        return self.name


class RecordFactory:
    @staticmethod
    def get_record(qtype: QType, qclass: QClass, bb: ByteBuffer, rdlength: int) -> RData:
        if qclass == QClass.IN or qtype == QType.OPT:

            if qtype == QType.A:
                rdata = ARecord(bb.read_plain(rdlength))
            elif qtype == QType.NS:
                rdata = NSRecord(bb, num_bytes=rdlength)
            elif qtype == QType.CNAME:
                rdata = CNAMERecord(bb, num_bytes=rdlength)
            elif qtype == QType.MX:
                rdata = MXRecord(bb, num_bytes=rdlength)
            elif qtype == QType.AAAA:
                rdata = AAAARecord(bb.read_plain(rdlength))
            elif qtype == QType.SOA:
                rdata = SOARecord(bb, num_bytes=rdlength)
            elif qtype == QType.OPT:
                rdata = OPTRecord(bb.read_plain(rdlength))
            else:
                rdata = RData(bb.read_plain(rdlength))

            return rdata
        else:
            raise NotImplementedError("Can only handle RRs of class IN or OPT qtype")
