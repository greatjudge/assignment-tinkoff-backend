import base64
import sys
import enum

from typing import Generator
from collections import deque
from typing import Deque

from abc import ABC, abstractmethod

import requests
from requests import RequestException


class CRC8Exception(Exception):
    pass


def send_request(url: str, data: bytes):
    return requests.post(url, data)


def b64_encode(s: bytes) -> bytes:
    return base64.urlsafe_b64encode(s).rstrip(b'=')


def b64_decode(s: bytes) -> bytes:
    s = s + b'=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


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


def uleb128_decode(b64decoded_string: bytes) -> Generator:
    result = 0
    shift = 0
    for i, byte in enumerate(b64decoded_string, 1):
        result |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            yield result, i
            result = 0
            shift = 0
        else:
            shift += 7


def decode_string(b64decoded_string: bytes) -> tuple[str, int]:
    str_len = b64decoded_string[0]
    string = [''] * str_len
    for i, code in enumerate(b64decoded_string[1:str_len+1]):
        string[i] = chr(code)
    return ''.join(string), str_len + 1


def encode_string(string: str) -> bytes:
    return bytes([len(string)] + [ord(ch) for ch in string])


def decode_array_of_str(b64decoded_string: bytes) -> list[str]:
    arr_length = b64decoded_string[0]
    lst = [''] * arr_length
    start, end, i = 1, 1, 0
    for i in range(arr_length):
        s, len_s = decode_string(b64decoded_string[start:])
        lst[i] = s
        start += len_s
    return lst


class ComputerCRC8:
    def __init__(self, generator: int):
        self.generator = generator
        self.crctable = self.calc_table(generator)

    def compute(self, input_bytes: bytes) -> int:
        crc = 0
        for byte in input_bytes:
            crc = self.crctable[byte ^ crc]
        return crc

    @staticmethod
    def calc_table(generator: int) -> list:
        crctable = [0] * 256
        for dividend in range(256):
            current_byte = dividend
            for bit in range(8):
                if current_byte & 0x80 != 0:
                    current_byte <<= 1
                    current_byte &= 255
                    current_byte ^= generator
                else:
                    current_byte <<= 1
                    current_byte &= 255
            crctable[dividend] = current_byte
        return crctable

    def valid_crc8(self, bytes_input: bytes, crc8: int):
        if self.compute(bytes_input) != crc8:
            raise CRC8Exception


def get_packets(b64decoded_string: bytes) -> Generator:
    start, end, cnt = 0, 0, 0
    while start < len(b64decoded_string) and cnt < len(b64decoded_string):
        end += b64decoded_string[start] + 2
        try:
            packet = Packet.from_bytes(b64decoded_string[start:end])
        except CRC8Exception:
            continue
        finally:
            start = end
            cnt += 1
        yield packet


class Command(enum.Enum):
    WHOISHERE = 1
    IAMHERE = 2
    GETSTATUS = 3
    STATUS = 4
    SETSTATUS = 5
    TICK = 6


class DeviceType(enum.Enum):
    SmartHub = 1
    EnvSensor = 2
    Switch = 3
    Lamp = 4
    Socket = 5
    Clock = 6


class Payload:
    def __init__(self, src: int, dst: int, serial: int,
                 dev_type: DeviceType, cmd: Command, cmd_body: bytes):
        self.src = src
        self.dst = dst
        self.serial = serial
        self.dev_type = dev_type
        self.cmd = cmd
        self.cmd_body = cmd_body

    @classmethod
    def from_bytes(cls, b64decoded_string: bytes):
        # TODO Error handling (StopIterations etc)
        decoder = uleb128_decode(b64decoded_string)
        src, _ = next(decoder)
        dst, _ = next(decoder)
        serial, length = next(decoder)
        dev_type = b64decoded_string[length]
        cmd = b64decoded_string[length + 1]
        return cls(src, dst, serial, DeviceType(dev_type),
                   Command(cmd), b64decoded_string[length + 2:])

    def encode(self) -> bytearray:
        encoded = bytearray()
        for val in (self.src, self.dst, self.serial):
            encoded.extend(uleb128_encode(val))
        encoded += self.dev_type.value.to_bytes(1, 'big')
        encoded += self.cmd.value.to_bytes(1, 'big')
        return encoded + self.cmd_body

    def __repr__(self):
        return f'{self.__class__.__name__}({self.src}, {self.dst},' \
               f' {self.serial}, {self.dev_type}, {self.cmd})'

    def __eq__(self, other):
        return (self.src == other.src and self.dst == other.dst
                and self.serial == other.serial
                and self.dev_type == other.dev_type
                and self.cmd == other.cmd
                and self.cmd_body == other.cmd_body)


class Packet:
    crc8_computer = ComputerCRC8(0x1D)

    def __init__(self, payload: Payload,
                 length: int | None = None,
                 crc8: int | None = None):
        self.payload = payload
        self.length = length
        self.crc8 = crc8

    @classmethod
    def from_bytes(cls, b64decoded_string: bytes):
        length = b64decoded_string[0]
        crc8 = b64decoded_string[-1]
        payload = Payload.from_bytes(b64decoded_string[1:-1])
        cls.crc8_computer.valid_crc8(b64decoded_string[1:-1], crc8)
        return cls(payload, length, crc8)

    def encode(self) -> bytearray:
        payload_bytes = self.payload.encode()
        crc8 = self.crc8_computer.compute(payload_bytes)
        return bytearray(len(payload_bytes).to_bytes(1, 'big')
                         + self.payload.encode()
                         + crc8.to_bytes(1, 'big'))

    def __repr__(self):
        return f'{self.__class__.__name__}({self.length}, {self.payload}, {self.crc8})'

    def __eq__(self, other):
        return (self.length == other.length
                and self.payload == other.payload
                and self.crc8 == other.crc8)


class Timer:
    def __init__(self):
        self.time = None

    @staticmethod
    def decode_tick(b64decoded_string: bytes) -> int:
        timestamp = next(uleb128_decode(b64decoded_string))[0]
        return timestamp


class AbsStatused(ABC):
    def reqstatus_expired(self, time: int):
        if self.is_connected and self.reqstatus_times:
            first_reqstatus_time = self.reqstatus_times[0]
            if time - first_reqstatus_time >= 300:
                self.is_connected = False
        return self.is_connected

    def _form_setstatus(self, smarthub, cmd_body: bytes) -> Packet:
        return Packet(
            Payload(
                smarthub.src, self.address,
                smarthub.serial, self.dev_type,
                Command.SETSTATUS, cmd_body
            )
        )

    def _form_getstatus(self, smarthub) -> Packet:
        return Packet(
            Payload(
                smarthub.src, self.address,
                smarthub.serial, self.dev_type,
                Command.GETSTATUS, b''
            )
        )

    @abstractmethod
    def _send_getstatus_actions(self, smarthub):
        pass

    @abstractmethod
    def _send_setstatus_actions(self, smarthub, status):
        pass

    def send_getstatus(self, smarthub):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(self)
        else:
            self._send_getstatus_actions(smarthub)
            self.reqstatus_times.appendleft(smarthub.timer.time)

    def send_setstatus(self, smarthub, status):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(self)
        else:
            self._send_setstatus_actions(smarthub, status)
            self.reqstatus_times.appendleft(smarthub.timer.time)

    @abstractmethod
    def _handle_status_actions(self, smarthub, cmd_body):
        pass

    def handle_status(self, smarthub, cmd_body):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(smarthub)
        else:
            self._handle_status_actions(smarthub, cmd_body)
            self.reqstatus_times.pop()


class Switch(AbsStatused):
    def __init__(self, name: str, device_names: list[str], address: int):
        self.dev_type = DeviceType.Switch
        self.name = name
        self.device_names = device_names
        self.address = address
        self.is_on = None

        self.is_connected = True
        self.reqstatus_times: Deque[int] = deque()

    def _send_getstatus_actions(self, smarthub):
        smarthub.packets_to_send.appendleft(self._form_getstatus(smarthub))

    def _send_setstatus_actions(self, smarthub, status):
        pass

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        self.is_on = bool(cmd_body[0])
        print('switch is on:', self.is_on, 'devices:')
        for dev_name in self.device_names:
            device = smarthub.name2device.get(dev_name)
            if device is not None:
                print(f'\t{device.name}')
                device.send_setstatus(smarthub, self.is_on)

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        # b64decoded_string - encoded cmd_body in whoishere, iamhere
        name, name_len = decode_string(cmd_body)
        devices = decode_array_of_str(cmd_body[name_len:])
        print(devices)
        return cls(name, devices, address)


class Lamp(AbsStatused):
    def __init__(self, name: str, address: int):
        self.dev_type = DeviceType.Lamp
        self.name = name
        self.address = address
        self.is_on = None

        self.is_connected = True
        self.reqstatus_times: Deque[int] = deque()

    def _send_setstatus_actions(self, smarthub, status: int):
        smarthub.packets_to_send.appendleft(
            self._form_setstatus(smarthub, status.to_bytes(1, 'big'))
        )

    def _send_getstatus_actions(self, smarthub):
        smarthub.packets_to_send.appendleft(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        print(f'LAMP SET: {bool(cmd_body[0])}')
        self.is_on = bool(cmd_body[0])

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, _ = decode_string(cmd_body)
        return cls(name, address)


class Socket(AbsStatused):
    def __init__(self, name: str, address: int):
        self.dev_type = DeviceType.Lamp
        self.name = name
        self.address = address
        self.is_on = None

        self.is_connected = True
        self.reqstatus_times: Deque[int] = deque()

    def _send_setstatus_actions(self, smarthub, status: int):
        smarthub.packets_to_send.appendleft(
            self._form_setstatus(smarthub, status.to_bytes(1, 'big'))
        )

    def _send_getstatus_actions(self, smarthub):
        smarthub.packets_to_send.appendleft(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        print(f'LAMP SET: {bool(cmd_body[0])}')
        self.is_on = bool(cmd_body[0])

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, _ = decode_string(cmd_body)
        return cls(name, address)


class EnvSensor(AbsStatused):
    def __init__(self, name: str, address: int,
                 sensors: int, triggers: list):
        self.name = name
        self.address = address
        self.sensors = sensors
        self.triggers = triggers

        self.is_connected = True
        self.reqstatus_times: Deque[int] = deque()



class DeviceBuilder:
    devtype2device = {
        DeviceType.Lamp: Lamp,
        DeviceType.Switch: Switch,
        DeviceType.Socket: Socket,
        DeviceType.EnvSensor: EnvSensor
    }

    def build_device_from_bytes(self, cmd_body: bytes,
                                dev_type: DeviceType, address: int):
        dev_class = self.devtype2device.get(dev_type)
        if dev_class is not None:
            return dev_class.from_bytes(cmd_body, address)
        return None


class SmartHub:
    def __init__(self, url: str, src: int, serial: int = 1):
        self.name = 'SmartHub'
        self.encoded_name = encode_string(self.name)
        self.url = url
        self.src = src
        self.serial = serial
        self.dev_type = DeviceType.SmartHub
        self.packets_to_send: Deque[Packet] = deque()

        self.device_builder = DeviceBuilder()
        self.devices = {}
        self.name2device = {}

        self.whoishere_time = None

    def _form_whoishere(self) -> Packet:
        return Packet(Payload(self.src, 0x3FFF,
                              self.serial, self.dev_type,
                              Command.WHOISHERE, self.encoded_name))

    def _form_iamhere(self) -> Packet:
        return Packet(Payload(self.src, 0x3FFF,
                              self.serial, self.dev_type,
                              Command.IAMHERE, self.encoded_name))

    def _add_device(self, device):
        self.devices[device.dev_type][device.address] = device
        self.name2device[device.name] = device

    def remove_device(self, device):
        self.devices[device.dev_type].pop(device.address, None)
        self.name2device.pop(device.name, None)

    def _handle_iamhere(self, packet: Packet):
        device = self.device_builder.build_device_from_bytes(
            packet.payload.cmd_body,
            packet.payload.dev_type,
            packet.payload.src
        )
        if device is not None:
            self._add_device(device)
            device.send_getstatus(self)

    def _handle_whoishere(self, packet: Packet):
        self.packets_to_send.appendleft(self._form_iamhere())
        self._handle_iamhere(packet)

    def _handle_status(self, packet: Packet):
        address = packet.payload.src
        device = self.devices[packet.payload.dev_type].get(address)
        if device is not None:
            device.handle_status(self, packet.payload.cmd_body)

    def start(self):

        self.timer = Timer()
        time_whoishere = None

        self.devices = {dev_type: {} for dev_type in DeviceType}
        self.name2device = {}
        self.packets_to_send: Deque[Packet] = deque()
        self.packets_to_send.appendleft(self._form_whoishere())

        while True:
            # Handle http error
            if self.packets_to_send:
                p = self.packets_to_send.pop()
                print('send packet:', p)
                p = p.encode()
            else:
                p = b''

            try:
                res = send_request(self.url, b64_encode(p))
                self.serial += 1
            except RequestException:
                sys.exit(99)

            if res.status_code == 200:
                print(f'{res.content=}')
                b64decoded_string = b64_decode(res.content)
                print(f'{b64decoded_string=}')

                packets = []
                current_time = None
                for packet in get_packets(b64decoded_string):
                    print(f'{packet=}')
                    if packet.payload.cmd == Command.TICK:
                        current_time = self.timer.decode_tick(packet.payload.cmd_body)
                    else:
                        packets.append(packet)
                if current_time is not None:
                    self.timer.time = current_time

                for packet in packets:
                    match packet.payload.cmd:
                        case Command.IAMHERE:
                            if time_whoishere is None:
                                time_whoishere = self.timer.time
                            if self.timer.time - time_whoishere < 300:
                                self._handle_iamhere(packet)
                        case Command.WHOISHERE:
                            self._handle_whoishere(packet)
                        case Command.STATUS:
                            print('HANDLE STATUS')
                            self._handle_status(packet)
            elif res.status_code == 204:
                sys.exit(0)
            else:
                sys.exit(99)
            print(self.devices)
            print(self.name2device)
            print()
            print()


def main(url: str, myaddr: int):
    hub = SmartHub(url, myaddr)
    hub.start()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        myaddr = int(sys.argv[2], 16)
        print(url, myaddr)
        print()
        main(url, myaddr)
    data = base64.urlsafe_b64encode(b'').rstrip(b'=')
    s = base64.urlsafe_b64decode('DbMG_38BBgaI0Kv6kzGK')
