import enum
from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property, wraps
from logging import getLogger
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vmess_aead.enums import VMessBodyCommand, VMessBodyOptions, VMessBodySecurity
from vmess_aead.kdf import kdf16
from vmess_aead.utils import (
    SM4GCM,
    Shake128Reader,
    fnv1a32,
    generate_chacha20_poly1305_key,
)
from vmess_aead.utils.reader import (
    BaseReader,
    BytesReader,
    ReadOutOfBoundError,
    StreamCipherReader,
)

logger = getLogger(__name__)


@dataclass
class _VMessBodyEncodingBase:
    body_key: bytes
    body_iv: bytes
    options: VMessBodyOptions
    security: VMessBodySecurity
    command: VMessBodyCommand
    authenticated_length_key: bytes | None = None
    authenticated_length_iv: bytes | None = None
    verify_checksum: bool = True

    def __post_init__(self):
        self._count = 0

    @property
    def count(self) -> int:
        return self._count & 0xFFFF

    @count.setter
    def count(self, value: int):
        self._count = value

    @cached_property
    def masker(self):
        return Shake128Reader(self.body_iv)

    @cached_property
    def aead(self):
        match self.security:
            case VMessBodySecurity.AES_128_GCM:
                return AESGCM(self.body_key)
            case VMessBodySecurity.CHACHA20_POLY1305:
                return ChaCha20Poly1305(generate_chacha20_poly1305_key(self.body_key))
            case VMessBodySecurity.SM4_GCM:
                return SM4GCM(self.body_key)
        return

    @property
    def aead_nonce(self) -> bytes:
        return self.count.to_bytes(2, "big") + self.body_iv[2:12]

    @cached_property
    def length_aead(self):
        length_key = kdf16(
            self.authenticated_length_key or self.body_key, [b"auth_len"]
        )
        match self.security:
            case VMessBodySecurity.AES_128_GCM:
                return AESGCM(length_key)
            case VMessBodySecurity.CHACHA20_POLY1305:
                return ChaCha20Poly1305(generate_chacha20_poly1305_key(length_key))
            case VMessBodySecurity.SM4_GCM:
                return SM4GCM(length_key)
        return

    @property
    def length_aead_nonce(self) -> bytes:
        length_iv = self.authenticated_length_iv or self.body_iv
        return self.count.to_bytes(2, "big") + length_iv[2:12]

    @cached_property
    def cipher_pair(self):
        if self.security is not VMessBodySecurity.AES_128_CFB:
            return
        return (
            Cipher(algorithms.AES(self.body_key), modes.CFB(self.body_iv)).encryptor(),
            Cipher(algorithms.AES(self.body_key), modes.CFB(self.body_iv)).decryptor(),
        )


@dataclass
class VMessBodyEncoder(_VMessBodyEncodingBase):
    def encode(
        self,
        data: bytes,
        padding_generator: Callable[[int], bytes] = token_bytes,
    ) -> bytes:
        if not self.options & VMessBodyOptions.CHUNK_STREAM:
            if self.cipher_pair is not None:
                encryptor, _ = self.cipher_pair
                return encryptor.update(data)
            elif self.security is VMessBodySecurity.NONE:
                return data

        match self.security:
            case VMessBodySecurity.AES_128_CFB:
                encrypted_data = fnv1a32(data).to_bytes(4, "big") + data
            case _ if self.aead is not None:
                encrypted_data = self.aead.encrypt(self.aead_nonce, data, None)
            case VMessBodySecurity.NONE:
                encrypted_data = data
            case _:  # pragma: no cover
                raise ValueError(f"Unknown {self.security=}")

        if self.options & VMessBodyOptions.GLOBAL_PADDING and not (
            self.security is VMessBodySecurity.NONE
            and self.command in (VMessBodyCommand.TCP, VMessBodyCommand.MUX)
        ):
            padding_length = self.masker.read_uint16() % 64
        else:
            padding_length = 0
        padding = padding_generator(padding_length)

        length = len(encrypted_data) + padding_length

        if (
            self.options & VMessBodyOptions.AUTHENTICATED_LENGTH
            and self.length_aead is not None
        ):
            encrypted_length = self.length_aead.encrypt(
                self.length_aead_nonce, (length - 16).to_bytes(2, "big"), None
            )
        elif self.options & VMessBodyOptions.CHUNK_MASKING:
            encrypted_length = (self.masker.read_uint16() ^ length).to_bytes(2, "big")
        else:
            encrypted_length = length.to_bytes(2, "big")

        packet = encrypted_length + encrypted_data + padding
        if self.cipher_pair is not None:
            encryptor, _ = self.cipher_pair
            packet = encryptor.update(packet)

        self.count += 1
        return packet


class VMessBodyDecoderState(enum.IntEnum):
    HEADER = enum.auto()
    DATA = enum.auto()
    PADDING = enum.auto()


@dataclass
class VMessBodyDecoder(_VMessBodyEncodingBase):
    def __post_init__(self):
        super().__post_init__()

        self.reader = BytesReader()
        match self.cipher_pair:
            case (_, decryptor):
                self.encrypted_reader = StreamCipherReader(self.reader, decryptor)
            case _:
                self.encrypted_reader = None
        self.state = VMessBodyDecoderState.HEADER
        self._decoder = self._decode()

    def decode(self, data: bytes):
        self.reader.append(data)

        chunks: list[bytes] = []
        for chunk in self._decoder:  # pragma: no branch
            if chunk is None:
                break
            chunks.append(chunk)
        return chunks

    def _decode(self):
        reader = self.encrypted_reader or self.reader

        content_length = None
        padding_length = 0
        while True:
            if not self.options & VMessBodyOptions.CHUNK_STREAM and (
                isinstance(reader, StreamCipherReader)
                or self.security is VMessBodySecurity.NONE
            ):
                self.state = VMessBodyDecoderState.DATA
                yield reader.read_all() if reader.remaining else None
                continue

            match self.state:
                case VMessBodyDecoderState.HEADER:
                    if not self.reader.remaining:
                        yield
                        continue
                    content_length = self._decode_header(reader)
                    if content_length is None:
                        yield
                        continue
                    self.state = VMessBodyDecoderState.DATA
                case VMessBodyDecoderState.DATA:
                    assert content_length is not None
                    length, padding_length = content_length
                    decrypted_data = self._decode_body(reader, length - padding_length)
                    if decrypted_data is None:
                        yield
                        continue
                    yield decrypted_data

                    if padding_length > 0:
                        self.state = VMessBodyDecoderState.PADDING
                    else:
                        self.state = VMessBodyDecoderState.HEADER
                case VMessBodyDecoderState.PADDING:
                    padding = self._decode_padding(reader, padding_length)
                    if padding is None:
                        yield
                        continue
                    self.state = VMessBodyDecoderState.HEADER
                case _:  # pragma: no cover
                    raise ValueError(f"Unknown {self.state=}")
        return

    @staticmethod
    def _fail_safe_decode[**P, R](func: Callable[P, R]) -> Callable[P, R | None]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs):
            try:
                return func(*args, **kwargs)
            except ReadOutOfBoundError as e:
                logger.debug(
                    "not enough data to decode, requested=%d, remaining=%d",
                    e.requested,
                    e.remaining,
                )
                return None

        return wrapper

    @_fail_safe_decode
    def _decode_header(self, reader: BaseReader):
        if (
            self.options & VMessBodyOptions.AUTHENTICATED_LENGTH
            and self.length_aead is not None
        ):
            encrypted_length = reader.read(2 + 16)
            decrypted_length = self.length_aead.decrypt(
                self.length_aead_nonce, encrypted_length, None
            )
            length = int.from_bytes(decrypted_length, "big") + 16
        elif self.options & VMessBodyOptions.CHUNK_MASKING:
            encrypted_length, length = reader.read_uint16(), None
        else:
            length = encrypted_length = reader.read_uint16()

        if self.options & VMessBodyOptions.GLOBAL_PADDING and not (
            self.security is VMessBodySecurity.NONE
            and self.command in (VMessBodyCommand.TCP, VMessBodyCommand.MUX)
        ):
            padding_length = self.masker.read_uint16() % 64
        else:
            padding_length = 0

        if length is None:
            assert isinstance(encrypted_length, int)
            length = encrypted_length ^ self.masker.read_uint16()

        return length, padding_length

    @_fail_safe_decode
    def _decode_body(self, reader: BaseReader, length: int):
        encrypted_data = reader.read(length)

        match self.security:
            case VMessBodySecurity.AES_128_CFB:
                checksum = int.from_bytes(encrypted_data[:4], "big")
                data = encrypted_data[4:]
                if self.verify_checksum and checksum != fnv1a32(data):
                    raise ValueError("Checksum mismatch")  # pragma: no cover
            case _ if self.aead is not None:
                data = self.aead.decrypt(self.aead_nonce, encrypted_data, None)
            case VMessBodySecurity.NONE:
                data = encrypted_data
            case _:  # pragma: no cover
                raise ValueError(f"Unknown {self.security=}")

        self.count += 1
        return data

    @_fail_safe_decode
    def _decode_padding(self, reader: BaseReader, padding_length: int):
        return reader.read(padding_length)
