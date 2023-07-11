from urllib.request import urlopen, Request
import base64
import sys
from typing import Generator


HOST = 'localhost'
PORT = 9998


def uleb128_encode(value: int) -> bytearray:
    if value < 0:
        raise ValueError('value must be >= 0')
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value == 0:
            result.append(byte)
            break
        result.append(byte | 0x80)
    return result


def uleb128_decode(values: bytes) -> Generator:
    result = 0
    shift = 0
    for i, byte in enumerate(values, 1):
        result |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            yield result, i
            result = 0
            shift = 0
        else:
            shift += 7


class Payload:
    def __init__(self, src, dst, serial, dev_type, cmd, device):
        self.src = src
        self.dst = dst
        self.serial = serial
        self.dev_type = dev_type
        self.cmd = cmd
        self.device = device

    @classmethod
    def from_bytes(cls, b64decoded_string: bytes):
        # TODO Error handling (StopIterations etc)
        decoder = uleb128_decode(b64decoded_string)
        src, _ = next(decoder)
        dst, _ = next(decoder)
        serial, length = next(decoder)
        dev_type = b64decoded_string[length]
        cmd = b64decoded_string[length + 1]
        # device = Device.from_bytes(b64decoded_string[length + 2:], cmd=cmd)
        timestamp, _ = next(uleb128_decode(b64decoded_string[length + 2:]))
        return cls(src, dst, serial, dev_type, cmd, timestamp)

    def encode(self) -> bytearray:
        encoded = bytearray()
        for val in (self.src, self.dst, self.serial):
            encoded.extend(uleb128_encode(val))
        encoded += self.dev_type.to_bytes(1, 'big')
        encoded += self.cmd.to_bytes(1, 'big')
        return encoded + uleb128_encode(self.device) # self.device.encode()

    def __repr__(self):
        return f'{self.__class__.__name__}({self.src}, {self.dst},' \
               f' {self.serial}, {self.dev_type}, {self.cmd}, {self.device})'

    def __eq__(self, other):
        # Добавил это, чтобы упростить код в тестах
        return (self.src == other.src and self.dst == other.dst
                and self.serial == other.serial
                and self.dev_type == other.dev_type
                and self.cmd == other.cmd
                and self.device == other.device)


class Packet:
    def __init__(self, length: int, payload: Payload, crc8: int):
        self.length = length
        self.payload = payload
        self.crc8 = crc8

    @classmethod
    def from_bytes(cls, b64decoded_string: bytes):
        length = b64decoded_string[0]
        crc8 = b64decoded_string[-1]
        payload = Payload.from_bytes(b64decoded_string[1:-1])
        return cls(length, payload, crc8)

    def encode(self):
        return (self.length.to_bytes(1, 'big')
                + self.payload.encode()
                + self.crc8.to_bytes(1, 'big'))

    def __repr__(self):
        return f'{self.__class__.__name__}({self.length}, {self.payload}, {self.crc8})'

    def __eq__(self, other):
        # Добавил это, чтобы упростить код в тестах
        return (self.length == other.length
                and self.payload == other.payload
                and self.crc8 == other.crc8)


def send_request(url: str, data):
    req = Request(url, data, method='POST')
    with urlopen(req) as resp:
        return resp
    
    
def main(url: str, myaddr: int):
    pass


if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        myaddr = int(sys.argv[2], 16)
        main(url, myaddr)
        print(url, myaddr)
    data = base64.urlsafe_b64encode(b'').rstrip(b'=')
    url = f'http://{HOST}:{PORT}/'
    s = base64.urlsafe_b64decode('DbMG_38BBgaI0Kv6kzGK')
