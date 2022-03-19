import binascii
import random
import socket
from typing import Union, Optional

from resolver.packet import DnsHeader, QType, DnsMessage, DnsQuestion, QClass, DnsResourceRecord, RCode


def recursive_resolve(domain_name: str, record_type: Union[QType, str] = QType.A):
    # Begin by choosing one of the root name servers - ask 1.1.1.1 for IPs of root name servers and choose one
    root_ns = lookup(".", "NS", server_ip="1.1.1.1", recursive=False)
    resolved_root_ns = root_ns.resolved_ns(target_section="answer")
    name, addr = random.choice(list(resolved_root_ns.items()))

    # TODO: remove after testing
    # Some root servers are overloaded / have protection / ?
    # and they dont respond more often
    addr = "192.12.94.30"

    # FQDN vs name -> sometimes this equality may break
    while not name == domain_name:
        res = lookup(domain_name, record_type, server_ip=addr, recursive=False)
        resolved_pairs = res.resolved_ns()
        answer_records = res.answer_records(filter_by_type=record_type)
        if answer_records:
            print(answer_records)
            break
        name, addr = random.choice(list(resolved_pairs.items()))


def lookup(domain_name: str,
           record_type: Union[str, QType],
           server_ip: str = "1.1.1.1",
           recursive: bool = True,
           opt_size: Optional[int] = 4096) -> DnsMessage:
    print(f"Querying {record_type} {domain_name} @{server_ip}...")
    server = (server_ip, 53)
    msg = create_query(domain_name, record_type, opt_size=None)
    msg.header.recursion_desired = recursive
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg.header.Z = 0b010
    try:
        # TESTING
        # msg.header.arcount = 1
        # built_msg = msg.build().hex()
        # built_msg += "00002904d000000000000c000a000801e606a00031bfec"   # Additional record
        # built_msg = binascii.unhexlify(built_msg)

        # This query always returns correctly
        built_msg = binascii.unhexlify("6af300200001000000000001057961686f6f03636f6d0000010001000029100000000000000"
                                       "c000a00087f8a8c72d252493b")

        sock.sendto(msg.build(), server)
        data, _ = sock.recvfrom(4096)
        response = DnsMessage().from_bytes(data)
        response.print_concise_info()
        return response
    finally:
        sock.close()


def create_query(domain_name: str, record_type: Union[str, QType], opt_size: Optional[int] = 4096) -> DnsMessage:
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

    msg = DnsMessage(header=header,
                     question=[question])

    if opt_size:
        opt = DnsResourceRecord().pseudo_record(domain_name=".", udp_payload_size=opt_size)
        msg.additional.append(opt)

    return msg
