import unittest

from resolver.resolver import ByteBuffer


class MyTestCase(unittest.TestCase):
    def test_read_qname(self):
        bb = ByteBuffer(buf=bytes.fromhex("026373086265726b656c65790365647500"))
        self.assertEqual(bb.read_qname(), "cs.berkeley.edu")


if __name__ == '__main__':
    unittest.main()
