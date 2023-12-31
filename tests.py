import unittest
from hub import (
    Packet, Payload, ComputerCRC8,
    uleb128_encode, Command, DeviceType,
    EnvSensor, b64_encode, b64_decode, Trigger
)
from unittest import mock


class TestCRC8Computer(unittest.TestCase):
    def setUp(self) -> None:
        self.computer = ComputerCRC8(0x1D)

    def test_table(self):
        table = [
            0x00, 0x1D, 0x3A, 0x27, 0x74, 0x69, 0x4E, 0x53, 0xE8, 0xF5, 0xD2, 0xCF, 0x9C, 0x81, 0xA6, 0xBB,
            0xCD, 0xD0, 0xF7, 0xEA, 0xB9, 0xA4, 0x83, 0x9E, 0x25, 0x38, 0x1F, 0x02, 0x51, 0x4C, 0x6B, 0x76,
            0x87, 0x9A, 0xBD, 0xA0, 0xF3, 0xEE, 0xC9, 0xD4, 0x6F, 0x72, 0x55, 0x48, 0x1B, 0x06, 0x21, 0x3C,
            0x4A, 0x57, 0x70, 0x6D, 0x3E, 0x23, 0x04, 0x19, 0xA2, 0xBF, 0x98, 0x85, 0xD6, 0xCB, 0xEC, 0xF1,
            0x13, 0x0E, 0x29, 0x34, 0x67, 0x7A, 0x5D, 0x40, 0xFB, 0xE6, 0xC1, 0xDC, 0x8F, 0x92, 0xB5, 0xA8,
            0xDE, 0xC3, 0xE4, 0xF9, 0xAA, 0xB7, 0x90, 0x8D, 0x36, 0x2B, 0x0C, 0x11, 0x42, 0x5F, 0x78, 0x65,
            0x94, 0x89, 0xAE, 0xB3, 0xE0, 0xFD, 0xDA, 0xC7, 0x7C, 0x61, 0x46, 0x5B, 0x08, 0x15, 0x32, 0x2F,
            0x59, 0x44, 0x63, 0x7E, 0x2D, 0x30, 0x17, 0x0A, 0xB1, 0xAC, 0x8B, 0x96, 0xC5, 0xD8, 0xFF, 0xE2,
            0x26, 0x3B, 0x1C, 0x01, 0x52, 0x4F, 0x68, 0x75, 0xCE, 0xD3, 0xF4, 0xE9, 0xBA, 0xA7, 0x80, 0x9D,
            0xEB, 0xF6, 0xD1, 0xCC, 0x9F, 0x82, 0xA5, 0xB8, 0x03, 0x1E, 0x39, 0x24, 0x77, 0x6A, 0x4D, 0x50,
            0xA1, 0xBC, 0x9B, 0x86, 0xD5, 0xC8, 0xEF, 0xF2, 0x49, 0x54, 0x73, 0x6E, 0x3D, 0x20, 0x07, 0x1A,
            0x6C, 0x71, 0x56, 0x4B, 0x18, 0x05, 0x22, 0x3F, 0x84, 0x99, 0xBE, 0xA3, 0xF0, 0xED, 0xCA, 0xD7,
            0x35, 0x28, 0x0F, 0x12, 0x41, 0x5C, 0x7B, 0x66, 0xDD, 0xC0, 0xE7, 0xFA, 0xA9, 0xB4, 0x93, 0x8E,
            0xF8, 0xE5, 0xC2, 0xDF, 0x8C, 0x91, 0xB6, 0xAB, 0x10, 0x0D, 0x2A, 0x37, 0x64, 0x79, 0x5E, 0x43,
            0xB2, 0xAF, 0x88, 0x95, 0xC6, 0xDB, 0xFC, 0xE1, 0x5A, 0x47, 0x60, 0x7D, 0x2E, 0x33, 0x14, 0x09,
            0x7F, 0x62, 0x45, 0x58, 0x0B, 0x16, 0x31, 0x2C, 0x97, 0x8A, 0xAD, 0xB0, 0xE3, 0xFE, 0xD9, 0xC4,
        ]
        self.assertEqual(self.computer.crctable, table)

    def test_compute(self):
        times = 1688984021000
        input_bytes = Payload(819, 16383, 1, DeviceType(6), Command(6), uleb128_encode(1688984021000)).encode()
        answer = 138
        self.assertEqual(answer, self.computer.compute(input_bytes))


class TestPacketDecode(unittest.TestCase):
    def test_timestamp(self):
        encoded_packet = b'DbMG_38BBgaI0Kv6kzGK'
        decoded_true = Packet(Payload(819, 16383, 1, DeviceType(6), Command(6), uleb128_encode(1688984021000)), 13, 138)
        self.assertEqual(Packet.from_bytes(b64_decode(encoded_packet)),
                         decoded_true)


class TestPacketEncode(unittest.TestCase):
    def test_timestamp(self):
        packet = Packet(Payload(819, 16383, 1, DeviceType(6), Command(6), uleb128_encode(1688984021000)), 13, 138)
        encoded_packet = b'DbMG_38BBgaI0Kv6kzGK'
        self.assertEqual(b64_encode(packet.encode()).rstrip(b'='),
                         encoded_packet)


class TestEnvSensor(unittest.TestCase):
    def test_whoishere(self):
        encoded_packet = b'OAL_fwMCAQhTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI03Q'
        packet = Packet.from_bytes(b64_decode(encoded_packet))
        with self.subTest():
            self.assertEqual(packet.length, 56)
            self.assertEqual(packet.payload.src, 2)
            self.assertEqual(packet.payload.dst, 16383)
            self.assertEqual(packet.payload.serial, 3)
            self.assertEqual(packet.payload.dev_type, DeviceType.EnvSensor)
            self.assertEqual(packet.payload.cmd, Command.WHOISHERE)
        env_sensor = EnvSensor.from_bytes(packet.payload.cmd_body, packet.payload.src)
        with self.subTest():
            self.assertEqual(env_sensor.address, packet.payload.src)
            self.assertEqual(env_sensor.name, 'SENSOR01')
            self.assertEqual(env_sensor.sensors, 15)
            self.assertEqual(env_sensor.triggers, {3: [Trigger(12, 100, "OTHER1"), Trigger(15, 1200, "OTHER2")],
                                                   0: [Trigger(0, 100012, "OTHER3")],
                                                   2: [Trigger(8, 0, "OTHER4")]})

    def test_status(self):
        encoded_packet = b'EQIBBgIEBKUB4AfUjgaMjfILrw'
        packet = Packet.from_bytes(b64_decode(encoded_packet))
        with self.subTest():
            self.assertEqual(packet.length, 17)
            self.assertEqual(packet.payload.src, 2)
            self.assertEqual(packet.payload.dst, 1)
            self.assertEqual(packet.payload.serial, 6)
            self.assertEqual(packet.payload.dev_type, DeviceType.EnvSensor)
            self.assertEqual(packet.payload.cmd, Command.STATUS)
        smarthub = mock.MagicMock()
        values = [165, 992, 100180, 24938124]
        triggers = {
            0: [mock.Mock()],
            1: [mock.Mock()],
            2: [mock.Mock()],
            3: [mock.Mock()]
        }
        for num, (trigger,) in triggers.items():
            trigger.react = mock.Mock()

        envsensor = EnvSensor(15, triggers, packet.payload.dst, 'name')
        envsensor._handle_status_actions(smarthub, packet.payload.cmd_body)
        for sensor_num, (trigger,) in triggers.items():
            self.assertEqual(trigger.react.mock_calls,
                             [mock.call(values[sensor_num], smarthub)])
