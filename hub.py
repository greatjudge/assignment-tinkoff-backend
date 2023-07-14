import base64
import sys
import enum

from typing import Generator
from collections import deque
from typing import Deque

from abc import ABC, abstractmethod

import requests
from requests import RequestException, Response


class CRC8Error(Exception):
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
    # yield byte, byte number (from 1)
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
    start, i = 1, 0
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
            raise CRC8Error


def get_packets(b64decoded_string: bytes) -> Generator:
    start, end, cnt = 0, 0, 0
    while start < len(b64decoded_string) and cnt < len(b64decoded_string):
        end += b64decoded_string[start] + 2
        try:
            packet = Packet.from_bytes(b64decoded_string[start:end])
        except CRC8Error:
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


class Device(ABC):
    dev_type = None

    def __init__(self, address: int, name: str):
        self.address = address
        self.name = name

    @classmethod
    @abstractmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        pass


class Status(Device):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_connected = True
        self.reqstatus_times: Deque[int] = deque()

    def reqstatus_expired(self, time: int):
        if self.is_connected and self.reqstatus_times:
            first_reqstatus_time = self.reqstatus_times[0]
            if time - first_reqstatus_time > 300:
                self.is_connected = False
        return not self.is_connected

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

    def send_getstatus(self, smarthub):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(self)
        else:
            self._send_getstatus_actions(smarthub)
            self.reqstatus_times.appendleft(smarthub.timer.time)

    @abstractmethod
    def _handle_status_actions(self, smarthub, cmd_body):
        pass

    def handle_status(self, smarthub, cmd_body):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(self)
        else:
            self._handle_status_actions(smarthub, cmd_body)
            if self.reqstatus_times:
                self.reqstatus_times.pop()


class StatusSet(Status):
    def _form_setstatus(self, smarthub, cmd_body: bytes) -> Packet:
        return Packet(
            Payload(
                smarthub.src, self.address,
                smarthub.serial, self.dev_type,
                Command.SETSTATUS, cmd_body
            )
        )

    @abstractmethod
    def _send_setstatus_actions(self, smarthub, status):
        pass

    def send_setstatus(self, smarthub, status):
        if self.reqstatus_expired(smarthub.timer.time):
            smarthub.remove_device(self)
        else:
            self._send_setstatus_actions(smarthub, status)
            self.reqstatus_times.appendleft(smarthub.timer.time)


class StatusManaged(StatusSet):
    @abstractmethod
    def change_poweron_status_to(self, smarthub, is_on):
        pass


class Switch(Status):
    dev_type = DeviceType.Switch

    def __init__(self, device_names: list[str], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.device_names = device_names

    def _send_getstatus_actions(self, smarthub):
        smarthub.send_packet(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        self.is_on = bool(cmd_body[0])
        for dev_name in self.device_names:
            device = smarthub.name2device.get(dev_name)
            if device is not None:
                print(f'\t{device.name}')
                device.send_setstatus(smarthub, self.is_on)

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, name_len = decode_string(cmd_body)
        devices = decode_array_of_str(cmd_body[name_len:])
        print(devices)
        return cls(devices, address, name)


class Lamp(StatusManaged):
    dev_type = DeviceType.Lamp

    def _send_setstatus_actions(self, smarthub, status: int):
        smarthub.send_packet(
            self._form_setstatus(smarthub, status.to_bytes(1, 'big'))
        )

    def _send_getstatus_actions(self, smarthub):
        smarthub.send_packet(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        self.is_on = bool(cmd_body[0])

    def change_poweron_status_to(self, smarthub, to_on: bool):
        self.send_setstatus(smarthub, to_on)

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, _ = decode_string(cmd_body)
        return cls(address, name)


class Socket(StatusManaged):
    dev_type = DeviceType.Socket

    def _send_setstatus_actions(self, smarthub, status: int):
        smarthub.smarthub.send_packet(
            self._form_setstatus(smarthub, status.to_bytes(1, 'big'))
        )

    def _send_getstatus_actions(self, smarthub):
        smarthub.send_packet(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body: bytes):
        self.is_on = bool(cmd_body[0])

    def change_poweron_status_to(self, smarthub, to_on: bool):
        self.send_setstatus(smarthub, to_on)

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, _ = decode_string(cmd_body)
        return cls(address, name)


class Trigger:
    def __init__(self, op: int, value: int, device_name: str):
        self.op = op
        self.value = value
        self.device_name = device_name

    def sensor_num(self) -> int:
        return (self.op & 12) >> 2

    def threshold_passed(self, value) -> bool:
        if self.op & 2 == 1:
            return value > self.value
        else:
            return value < self.value

    def react(self, value: int, smarthub):
        if self.threshold_passed(value):
            device = smarthub.name2device.get(self.device_name)
            if device is not None:
                device.change_poweron_status_to(bool(self.op & 1))

    @classmethod
    def trig_and_len_from_bytes(cls, encoded_trigger):
        op = encoded_trigger[0]
        value, length = next(uleb128_decode(encoded_trigger[1:]))
        name, str_len = decode_string(encoded_trigger[1 + length:])  # + 1 because of op
        return cls(op, value, name), 1 + length + str_len


class EnvSensor(Status):
    dev_type = DeviceType.EnvSensor

    def __init__(self, sensors: int,
                 triggers: dict[int, list[Trigger]],
                 *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensors = sensors
        self.triggers = triggers

    def sensor_exist(self, sensor_num) -> bool:
        # sensor_num = 0, 1, 2, 3
        return self.sensors & 2**sensor_num == 1

    def _send_getstatus_actions(self, smarthub):
        smarthub.packets_to_send.appendleft(self._form_getstatus(smarthub))

    def _handle_status_actions(self, smarthub, cmd_body):
        sensor_num = 0
        for value in uleb128_decode(cmd_body):
            while not self.sensor_exist(sensor_num):
                sensor_num += 1
            for trigger in self.triggers.get(sensor_num, []):
                trigger.react(value, smarthub)
            sensor_num += 1

    @classmethod
    def from_bytes(cls, cmd_body: bytes, address: int):
        name, length = decode_string(cmd_body)
        sensors = cmd_body[length]
        triggers = cls._decode_triggers(cmd_body[length+1:])
        return cls(sensors, triggers, address, name)

    @classmethod
    def _decode_triggers(cls, triggers_array: bytes) -> dict[int, list[Trigger]]:
        # return dict sensor_num: trigger
        length = triggers_array[0]
        triggers = {}
        start, end, i = 1, 1, 0
        for i in range(length):
            trigger, tr_len = Trigger.trig_and_len_from_bytes(triggers_array[start:])
            triggers.setdefault(trigger.sensor_num, []).append(trigger)
            start += tr_len
        return triggers


class DeviceBuilder:
    devtype2device = {
        DeviceType.Lamp: Lamp,
        DeviceType.Switch: Switch,
        DeviceType.Socket: Socket,
        DeviceType.EnvSensor: EnvSensor
    }

    def build_device_from_bytes(self,
                                cmd_body: bytes,
                                dev_type: DeviceType,
                                address: int):
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
        self.dev_type = DeviceType.SmartHub
        self._serial = serial

        self.responses: Deque[Response] = deque()

        self._device_builder = DeviceBuilder()
        self._devices = {dev_type: {} for dev_type in DeviceType}
        self.name2device = {}

        self.timer = Timer()
        self._whoishere_time = None

    @property
    def serial(self):
        return self._serial

    def _form_whoishere(self) -> Packet:
        return Packet(Payload(self.src, 0x3FFF,
                              self._serial, self.dev_type,
                              Command.WHOISHERE, self.encoded_name))

    def _form_iamhere(self) -> Packet:
        return Packet(Payload(self.src, 0x3FFF,
                              self._serial, self.dev_type,
                              Command.IAMHERE, self.encoded_name))

    def _add_device(self, device):
        self._devices.setdefault(device.dev_type, {})[device.address] = device
        self.name2device[device.name] = device

    def remove_device(self, device):
        self._devices.get(device.dev_type, {}).pop(device.address, None)
        self.name2device.pop(device.name, None)

    def _handle_iamhere(self, packet: Packet):
        device = self._device_builder.build_device_from_bytes(
            packet.payload.cmd_body,
            packet.payload.dev_type,
            packet.payload.src
        )
        if device is not None:
            self._add_device(device)
            device.send_getstatus(self)

    def _handle_whoishere(self, packet: Packet):
        self.send_packet(self._form_iamhere())
        self._handle_iamhere(packet)

    def _handle_status(self, packet: Packet):
        address = packet.payload.src
        device = self._devices[packet.payload.dev_type].get(address)
        if device is not None:
            device.handle_status(self, packet.payload.cmd_body)

    def _send_encoded(self, packet: bytes):
        try:
            res = send_request(self.url, packet)
        except RequestException:
            sys.exit(99)
        self.responses.appendleft(res)

    def send_packet(self, packet: Packet):
        self._send_encoded(b64_encode(packet.encode()))
        self._serial += 1

    def start(self):
        self.send_packet(self._form_whoishere())

        while True:
            if not self.responses:
                self._send_encoded(b'')
            res = self.responses.pop()

            if res.status_code == 200:
                b64decoded_string = b64_decode(res.content)

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
                            if self._whoishere_time is None:
                                self._whoishere_time = self.timer.time
                            if self.timer.time - self._whoishere_time <= 300:
                                self._handle_iamhere(packet)
                        case Command.WHOISHERE:
                            self._handle_whoishere(packet)
                        case Command.STATUS:
                            self._handle_status(packet)
            elif res.status_code == 204:
                sys.exit(0)
            else:
                sys.exit(99)


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
