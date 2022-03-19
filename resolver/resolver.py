import binascii
import ipaddress
import random
import socket
from typing import Union, Optional

from resolver.packet import DnsHeader, QType, DnsMessage, DnsQuestion, QClass, DnsResourceRecord


def lookup(domain_name: str,
           record_type: Union[str, QType],
           server_ip: str = "1.1.1.1",
           recursive: bool = True,
           opt_size: Optional[int] = 4096) -> DnsMessage:
    server = (server_ip, 53)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = create_query(domain_name, record_type, opt_size)
    msg.header.recursion_desired = recursive
    try:
        sock.sendto(msg.build(), server)
        data, _ = sock.recvfrom(4096)
        response = DnsMessage().from_bytes(data)
        response.print_concise_info()
        return response
    except OSError:
        print(f"Lookup for {domain_name} @{server_ip} failed.")
    finally:
        sock.close()


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
