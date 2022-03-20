import binascii
import unittest

from resolver.packet import DnsHeader, DnsQuestion, QType, QClass, DnsResourceRecord, DnsMessage
from resolver.buffer import ByteBuffer
from resolver.packet import RCode

RESPONSE_NS_ROOT = "1b9d81800001000e0000001a0000020001000002000100070bf2001401660c726f6f742d73657276657273036e657400" \
                   "000002000100070bf200040163c01e000002000100070bf20004016ac01e000002000100070bf20004016dc01e000002" \
                   "000100070bf20004016bc01e000002000100070bf200040165c01e000002000100070bf20004016cc01e000002000100" \
                   "070bf200040162c01e000002000100070bf200040161c01e000002000100070bf200040164c01e000002000100070bf2" \
                   "00040169c01e000002000100070bf200040167c01e000002000100070bf200040168c01e00002e000100070bf2011300" \
                   "0208000007e9006243e3d06232b2402647001dfbd924aea41fac479152a8b01572487d61d43af61a4f15a0a07d6c5dc2" \
                   "0430493b9a4789368867f773c73e53c44fba1d36483e8680c5d16be32c9b300e899471acecc115330ebedb2613904bf0" \
                   "9c460ee514fa3a7548f0c62d628312d3e170fe204767d56966e0f66c71ee81c88a560d36f4db9e155549cfb18d8e3037" \
                   "3b7309b7b3776fc739156e745a08fb981dce58fee3c5a4a6a3738ae406d1ff1c93544a6e8f1b2473e6ddeb32170c8662" \
                   "502dcc5b381c77d4517217550da09d6e17f5fac200b661a91869caf5fc93eebef1eaeece2e22c88665cce9462610ffcd" \
                   "17e1554f43e56eb4fe0c21a9a09655e7696643f4b6f48b9e0743a49167a5f02a6a09c0e000010001000860680004c661" \
                   "be35c0e0001c000100086068001020010500000100000000000000000053c01c00010001000861050004c00505f1c01c" \
                   "001c000100088d14001020010500002f0000000000000000000fc03b0001000100085dc00004c021040cc03b001c0001" \
                   "000888ee00102001050000020000000000000000000cc04a0001000100085f590004c03a801ec04a001c0001000861f4" \
                   "0010200105030c2700000000000000020030c0590001000100085d980004ca0c1b21c059001c000100085dd000102001" \
                   "0dc3000000000000000000000035c0680001000100085d740004c1000e81c068001c0001000860d10010200107fd0000" \
                   "00000000000000000001c07700010001000881750004c0cbe60ac077001c00010008675400102001050000a800000000" \
                   "00000000000ec086000100010008609f0004c707532ac086001c000100087009001020010500009f0000000000000000" \
                   "0042c0950001000100085dbb0004c7090ec9c0a40001000100085d700004c6290004c0a4001c0001000861a300102001" \
                   "0503ba3e00000000000000020030c0b300010001000861f00004c7075b0dc0b3001c0001000861f0001020010500002d" \
                   "0000000000000000000dc0c200010001000861ec0004c0249411c0c2001c000100085ff90010200107fe000000000000" \
                   "000000000053c0d10001000100089b130004c0702404c0d1001c000100088d1400102001050000120000000000000000" \
                   "0d0d0000290200000080000000"

QUERY_A_ROOT_SERVER = "e2b40100000100000000000001630c726f6f742d73657276657273036e65740000010001"

QUERY_A_BERKELEY = "026373086265726b656c6579036564750000010001"

RESPONSE_DNS_FRAME_A_WITH_JUMP = "08758180000100010000000001680c726f6f742d73657276657273036e65740000010001c00c0" \
                                 "0010001000882c00004c661be35"

RESPONSE_A_NS_BERKELEY = "62a6818000010001000000000561646e7333086265726b656c6579036564750000010001c00c0001000100002a" \
                         "300004c06b668e"

RR_A_WITH_JUMP__ = "c00c00010001000882c00004c661be35"


class MyTestCase(unittest.TestCase):
    def test_read_plain(self):
        bb = ByteBuffer(buf=bytes.fromhex("026373086265726b656c65790365647500"))
        actual = bb.read_plain(4)
        expected = "02637308"
        self.assertEqual(expected, actual)

    def test_read_qname(self):
        bb = ByteBuffer(buf=bytes.fromhex("026373086265726b656c65790365647500"))
        self.assertEqual(bb.read_qname(), "cs.berkeley.edu")
        self.assertEqual(bb.pos, len(bb.buf))

    def test_read_qname_jump_dnsrecord(self):
        bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_DNS_FRAME_A_WITH_JUMP))
        expected = "h.root-servers.net"
        _ = DnsHeader().from_buffer(bb)  # Skip and discard header

        question = DnsQuestion().from_buffer(bb)
        actual_no_jump = question.name

        record_a = DnsResourceRecord().from_buffer(bb)
        actual_with_jump = record_a.name

        # Name without and with jump:
        self.assertEqual(expected, actual_no_jump)
        self.assertEqual(expected, actual_with_jump)

        # DNS RR correctness
        self.assertEqual(QType.A, record_a.qtype)
        self.assertEqual(QClass.IN, record_a.qclass)
        self.assertEqual(557760, record_a.ttl)
        self.assertEqual(4, record_a.rdlength)
        self.assertEqual("198.97.190.53", str(record_a.rdata))

    def test_read_header_manual(self):
        bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_NS_ROOT))
        ID = bb.read_uint16()
        flags = bb.read_uint16()
        QDCOUNT = bb.read_uint16()
        ANCOUNT = bb.read_uint16()
        NSCOUNT = bb.read_uint16()
        ARCOUNT = bb.read_uint16()
        self.assertEqual(int("0x1b9d", 16), ID)
        self.assertEqual(1, QDCOUNT)
        self.assertEqual(14, ANCOUNT)
        self.assertEqual(0, NSCOUNT)
        self.assertEqual(26, ARCOUNT)

    def test_read_uint16(self):
        """NS query for . <<Root>>, type IN, transaction_id = 0x1b9d"""
        bb = ByteBuffer(
            buf=bytes.fromhex("1b9d012000010000000000010000020001000029100000008000000c000a00088fca20a18356efef"))
        transaction_id = bb.read_uint16()
        self.assertEqual(int("0x1b9d", 16), transaction_id)

    def test_dnsheader_read(self):
        bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_NS_ROOT))
        header = DnsHeader().from_buffer(bb)
        self.assertEqual(int("0x1b9d", 16), header.ID)
        self.assertEqual(True, header.response)
        self.assertEqual(0, header.opcode)
        self.assertEqual(False, header.authoritative_answer)
        self.assertEqual(False, header.truncation)
        self.assertEqual(True, header.recursion_desired)
        self.assertEqual(True, header.recursion_available)
        self.assertEqual(0, header.Z)
        self.assertEqual(RCode.NO_ERROR, header.response_code)
        self.assertEqual(1, header.qdcount)
        self.assertEqual(14, header.ancount)
        self.assertEqual(0, header.nscount)
        self.assertEqual(26, header.arcount)

    def test_dnsheader_build(self):
        bb = ByteBuffer(buf=bytes.fromhex(RESPONSE_NS_ROOT))
        header = DnsHeader().from_buffer(bb)
        message = header.build()
        self.assertEqual("1b9d81800001000e0000001a", message)

    def test_read_question(self):
        bb = ByteBuffer(buf=bytes.fromhex(QUERY_A_BERKELEY))
        question = DnsQuestion().from_buffer(bb)
        self.assertEqual("cs.berkeley.edu", question.name)
        self.assertEqual(QType.A, question.qtype)
        self.assertEqual(QClass.IN, question.qclass)

    def test_question_rebuild(self):
        bb = ByteBuffer(buf=bytes.fromhex(QUERY_A_BERKELEY))
        question = DnsQuestion().from_buffer(bb)
        message = question.build()
        self.assertEqual(QUERY_A_BERKELEY, message)


if __name__ == '__main__':
    unittest.main()
