import binascii
import socket

from resolver.resolver import DnsMessage, ByteBuffer, DnsHeader, DnsQuestion, QType, QClass
from tests.resolver_test import RESPONSE_NS_ROOT, QUERY_A_ROOT_SERVER, RESPONSE_A_NS_BERKELEY

if __name__ == "__main__":
    bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_A_NS_BERKELEY))
    msg = DnsMessage().from_buffer(bb)
    # print(msg)

    # Header and question
    header = DnsHeader(qdcount=1)
    q1 = DnsQuestion(name="cs.berkeley.edu", qtype=QType.A)

    # OPT needed for query for NS . - why, payload size?

    q2 = DnsQuestion(name="com", qtype=QType.NS, qclass=QClass.IN)
    q3 = DnsQuestion(name="edu.pl", qtype=QType.NS, qclass=QClass.IN)
    q4 = DnsQuestion(name="i-dns.pl", qtype=QType.A, qclass=QClass.IN)

    # Build message
    message = DnsMessage()
    message.header = header
    message.question = [q4]

    built_message = binascii.unhexlify(message.build())

    server_params = ("1.1.1.1", 53)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(built_message, server_params)
        data, _ = sock.recvfrom(4096)
        bb = ByteBuffer(buf=data)
        response = DnsMessage().from_buffer(bb)
        print(response)
    finally:
        sock.close()
