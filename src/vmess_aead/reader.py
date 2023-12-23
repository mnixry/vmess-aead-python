import abc
import socket
from typing import IO


class ReadOutOfBoundError(ValueError):
    pass


class BaseReader(abc.ABC):
    @abc.abstractproperty
    def offset(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def read(self, length: int) -> bytes:
        raise NotImplementedError()

    def read_byte(self) -> int:
        return self.read(1)[0]

    def read_uint16(self) -> int:
        return int.from_bytes(self.read(2), "big")

    def read_uint32(self) -> int:
        return int.from_bytes(self.read(4), "big")

    def read_uint64(self) -> int:
        return int.from_bytes(self.read(8), "big")

    def read_uint128(self) -> int:
        return int.from_bytes(self.read(16), "big")


class BufferedReader(BaseReader):
    def __init__(self, reader: BaseReader):
        self._reader = reader
        self._buffer = b""
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def read(self, length: int) -> bytes:
        received = self._reader.read(length)
        self._buffer += received
        self._offset += length
        return received

    def read_before(self) -> bytes:
        return self._buffer[: self._offset]


class BytesReader(BaseReader):
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def read(self, length: int) -> bytes:
        if self._offset + length > len(self._data):
            raise ReadOutOfBoundError()
        result = self._data[self._offset : self._offset + length]
        self._offset += length
        return result

    def read_all(self) -> bytes:
        return self.read(len(self._data) - self._offset)

    def read_before(self) -> bytes:
        return self._data[: self._offset]


class IOReader(BaseReader):
    def __init__(self, io: IO[bytes]):
        self._io = io
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def read(self, length: int) -> bytes:
        result = self._io.read(length)
        if len(result) != length:
            raise ReadOutOfBoundError()
        self._offset += length
        return result

    def read_all(self) -> bytes:
        return self._io.read()


class SocketReader(BaseReader):
    def __init__(self, socket: socket.socket, buffer_size: int = 1024):
        self._socket = socket
        self._offset = 0
        self._buffer = b""
        self._buffer_size = buffer_size

    @property
    def offset(self) -> int:
        return self._offset

    def read(self, length: int) -> bytes:
        while len(self._buffer) < length:
            received = self._socket.recv(self._buffer_size)
            if not received:
                raise ReadOutOfBoundError()
            self._buffer += received
        result = self._buffer[:length]
        self._buffer = self._buffer[length:]
        self._offset += length
        return result

    def read_all(self) -> bytes:
        while True:
            received = self._socket.recv(self._buffer_size)
            if not received:
                break
            self._buffer += received
        return self._buffer
