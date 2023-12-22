class StatefulReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def read(self, length: int) -> bytes:
        if self._offset + length > len(self._data):
            raise ValueError("Read out of bound")
        result = self._data[self._offset : self._offset + length]
        self._offset += length
        return result

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

    def read_all(self) -> bytes:
        return self.read(len(self._data) - self._offset)

    def read_all_before(self) -> bytes:
        return self._data[: self._offset]
