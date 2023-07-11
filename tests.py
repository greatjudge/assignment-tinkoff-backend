import unittest
import base64
from hub import Packet, Payload


class TestPacketDecode(unittest.TestCase):
    def test_timestamp(self):
        encoded_packet = 'DbMG_38BBgaI0Kv6kzGK'
        decoded_true = Packet(13, Payload(819, 16383, 1, 6, 6, 1688984021000), 138)
        self.assertEqual(Packet.from_bytes(base64.urlsafe_b64decode(encoded_packet)),
                         decoded_true)


class TestPacketEncode(unittest.TestCase):
    def test_timestamp(self):
        packet = Packet(13, Payload(819, 16383, 1, 6, 6, 1688984021000), 138)
        encoded_packet = b'DbMG_38BBgaI0Kv6kzGK'
        self.assertEqual(base64.urlsafe_b64encode(packet.encode()).rstrip(b'='),
                         encoded_packet)
