import abc
from typing import IO

from cryptography.hazmat.primitives.ciphers import CipherContext


class ReadOutOfBoundError(ValueError):
    def __init__(self, requested: int, remaining: int, *args) -> None:
        super().__init__(
            f"Requested {requested} bytes, but only {remaining} bytes remaining",
            *args,
        )
        self.requested = requested
        self.remaining = remaining


class BaseReader(abc.ABC):
    @property
    @abc.abstractmethod
    def offset(self) -> int:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def remaining(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def read(self, length: int) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def read_all(self) -> bytes:
        raise NotImplementedError

    def read_byte(self) -> int:
        return self.read(1)[0]

    def read_until(self, delimiter: bytes) -> bytes:
        data = b""
        while not data.endswith(delimiter):
            data += self.read(1)
        return data

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

    @property
    def offset(self) -> int:
        return self._reader.offset

    @property
    def remaining(self) -> int:
        return self._reader.remaining

    def read(self, length: int) -> bytes:
        received = self._reader.read(length)
        self._buffer += received
        return received

    def read_before(self) -> bytes:
        return self._buffer[: self.offset]

    def read_all(self) -> bytes:
        return self._reader.read_all()


class BytesReader(BaseReader):
    def __init__(self, data: bytes | None = None):
        self._data = bytearray(data or b"")
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return len(self._data)

    def read(self, length: int) -> bytes:
        if length > self.remaining:
            raise ReadOutOfBoundError(length, self.remaining)
        result = self._data[:length]
        self._offset += length
        del self._data[:length]
        return bytes(result)

    def append(self, data: bytes) -> None:
        self._data.extend(data)

    def read_all(self) -> bytes:
        return self.read(self.remaining)


class IOReader(BaseReader):
    def __init__(self, io: IO[bytes]):
        self._io = io
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        if not self._io.seekable():
            raise NotImplementedError("Read remaining bytes from non-seekable IO")
        return self._io.seek(0, 2) - self._offset

    def read(self, length: int) -> bytes:
        result = self._io.read(length)
        if len(result) != length:
            raise ReadOutOfBoundError(length, len(result))
        self._offset += length
        return result

    def read_all(self) -> bytes:
        data = self._io.read()
        self._offset += len(data)
        return data


class StreamCipherReader(BaseReader):
    def __init__(self, reader: BaseReader, cipher: CipherContext):
        self._reader = reader
        self._cipher = cipher
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return self._reader.remaining

    def read(self, length: int) -> bytes:
        data = self._reader.read(length)
        self._offset += length
        return self._cipher.update(data)

    def read_all(self) -> bytes:
        data = self._reader.read_all()
        self._offset += len(data)
        return self._cipher.update(data)
