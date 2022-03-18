from resolver.resolver import DnsMessage, ByteBuffer
from tests.resolver_test import RESPONSE_NS_ROOT, QUERY_A_ROOT_SERVER

if __name__ == "__main__":
    bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_NS_ROOT))
    msg = DnsMessage().from_buffer(bb)

    print(msg.header)
    print("")

    for ans in msg.answer:
        print(ans)
        print("")
