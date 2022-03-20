import binascii
import random
import socket
from typing import Union, Optional

from resolver.packet import DnsHeader, QType, DnsMessage, DnsQuestion, QClass, DnsResourceRecord, RCode


def recursive_resolve(domain_name: str, record_type: Union[QType, str] = QType.A):
    # Begin by choosing one of the root name servers - ask 1.1.1.1 for IPs of root name servers and choose one
    root_ns = lookup(".", "NS", server_ip="1.1.1.1", recursive=False, verbose=False)
    # root_ns.print_concise_info(sections={"answer"})
    resolved_root_ns = root_ns.resolved_ns(target_section="answer")
    name, addr = random.choice(list(resolved_root_ns.items()))

    # SOA, CNAME logic is still left to be implemented
    while not name == domain_name:
        res = lookup(domain_name, record_type, server_ip=addr, recursive=False, verbose=False)

        res.print_concise_info()

        resolved_pairs = res.resolved_ns()
        unresolved_ns = res.authority_ns()
        if resolved_pairs:
            name, addr = random.choice(list(resolved_pairs.items()))
        elif unresolved_ns:
            # TODO - implement logic
            # DNS server didn't provide ips of NS in additional section
            name = random.choice(unresolved_ns)

        # if resolved_pairs or unresolved_ns:
        #     res.print_concise_info(sections={"authority"})

        answer_records = res.answer_records(filter_by_type=record_type)
        if answer_records:
            # res.print_concise_info(sections={"answer"})
            break


def lookup(domain_name: str,
           record_type: Union[str, QType],
           server_ip: str = "1.1.1.1",
           recursive: bool = True,
           opt_size: Optional[int] = 4096,
           verbose: bool = True) -> DnsMessage:
    print(f"Querying {record_type} {domain_name} @{server_ip}...")
    server = (server_ip, 53)
    msg = create_query(domain_name, record_type, opt_size)
    msg.header.recursion_desired = recursive
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg.build(), server)
        data, _ = sock.recvfrom(4096)
        response = DnsMessage().from_bytes(data)
        if verbose:
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
            print(f"QType {record_type} not supported")
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
