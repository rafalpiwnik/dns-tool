from resolver.resolver import DnsMessage, ByteBuffer
from tests.resolver_test import RESPONSE_NS_ROOT, QUERY_A_ROOT_SERVER, RESPONSE_A_NS_BERKELEY

if __name__ == "__main__":
    bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_A_NS_BERKELEY))
    msg = DnsMessage().from_buffer(bb)

    print(msg)
