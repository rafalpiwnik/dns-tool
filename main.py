from resolver.resolver import build_header, build_question, DnsHeader
from resolver import ByteBuffer

if __name__ == "__main__":
    build_header()
    print(build_question("cs.berkeley.edu"))
    bb = ByteBuffer(buf=bytes.fromhex("026373086265726b656c65790365647500"))

    print(bb.read_qname())
