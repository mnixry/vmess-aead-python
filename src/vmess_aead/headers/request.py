import itertools
from binascii import crc32
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union
from uuid import UUID

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.reader import BaseReader, BytesReader
from vmess_aead.utils import (
    Shake128Stream,
    cmd_key,
    fnv1a32,
    generate_chacha20_poly1305_key,
)


@dataclass
class VMessAuthID:
    timestamp: int
    """Timestamp in seconds, uint64, big endian"""
    rand: bytes
    """Random bytes, 4 bytes"""

    @classmethod
    def from_packet(cls, encrypted: bytes, user_id: UUID, verify_checksum: bool = True):
        decrypted = cls._decrypt(
            encrypted, kdf16(cmd_key(user_id), [KDFSaltConst.AUTH_ID_ENCRYPTION_KEY])
        )
        reader = BytesReader(decrypted)
        timestamp = reader.read_uint64()
        rand = reader.read(4)
        checksum_body = reader.read_before()
        checksum = reader.read_uint32()
        if verify_checksum:
            assert checksum == crc32(checksum_body)
        return cls(timestamp, rand)

    @staticmethod
    def _decrypt(encrypted: bytes, key: bytes) -> bytes:
        assert len(encrypted) == 16  # aes-128 block size
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_auth_id = decryptor.update(encrypted) + decryptor.finalize()
        assert len(decrypted_auth_id) == 16
        return decrypted_auth_id


@dataclass
class VMessPlainPacketHeader:
    version: int
    """Version, uint8"""
    body_iv: bytes
    """Body IV, 16 bytes"""
    body_key: bytes
    """Body key, 16 bytes"""
    response_header: int
    """Response header, uint8"""
    options: VMessBodyOptions
    """Options, uint8 (bitmask)"""
    padding_length: int
    """Padding length, high 4 bits of uint8"""
    security: VMessBodySecurity
    """Security, low 4 bits of uint8"""
    reserved: int
    """Reserved, uint8"""
    command: VMessBodyCommand
    """Command, uint8"""
    port: int
    """Port, uint16, big endian"""
    address_type: VMessBodyAddressType
    """Address type, uint8"""
    address: Union[IPv4Address, IPv6Address, str]
    """Address, variable length"""

    @classmethod
    def from_packet(cls, packet: bytes, verify_checksum: bool = True):
        reader = BytesReader(packet)
        version = reader.read_byte()
        body_iv = reader.read(16)
        body_key = reader.read(16)
        response_header = reader.read_byte()
        options = VMessBodyOptions(reader.read_byte())
        padding_length_and_security = reader.read_byte()
        padding_length = padding_length_and_security >> 4
        security = VMessBodySecurity(padding_length_and_security & 0x0F)
        reserved = reader.read_byte()
        command = VMessBodyCommand(reader.read_byte())
        port = reader.read_uint16()
        address_type = VMessBodyAddressType(reader.read_byte())
        if address_type is VMessBodyAddressType.IPV4:
            address = IPv4Address(reader.read_uint32())
        elif address_type is VMessBodyAddressType.DOMAIN:
            domain_length = reader.read_byte()
            address = reader.read(domain_length).decode()
        elif address_type is VMessBodyAddressType.IPV6:
            address = IPv6Address(reader.read_uint128())
        else:
            raise ValueError(f"Unknown address type: {address_type!r}")
        if padding_length > 0:
            reader.read(padding_length)
        checksum_body = reader.read_before()
        checksum = reader.read_uint32()
        if verify_checksum:
            assert checksum == fnv1a32(checksum_body)
        return cls(
            version,
            body_iv,
            body_key,
            response_header,
            options,
            padding_length,
            security,
            reserved,
            command,
            port,
            address_type,
            address,
        )


@dataclass
class VMessAEADRequestPacketHeader:
    """Packet send from client to server"""

    auth_id: VMessAuthID
    """Authentication ID"""
    length: int
    """Length of the payload, uint16, big endian"""
    nonce: bytes
    """Nonce, 8 bytes"""
    payload: VMessPlainPacketHeader
    """Payload"""
    read_offset: int
    """Offset after reading the header"""

    @classmethod
    def from_packet(
        cls,
        reader: BaseReader,
        user_id: UUID,
        *,
        verify_checksum: bool = True,
        timestamp: Optional[int] = None,
        timestamp_range: int = 2 * 60,
    ):
        encrypted_auth_id = reader.read(16)
        auth_id = VMessAuthID.from_packet(encrypted_auth_id, user_id, verify_checksum)
        if timestamp is not None:
            assert abs(timestamp - auth_id.timestamp) <= timestamp_range
        encrypted_header_length = reader.read(2 + 16)  # AEAD tag size is 16 bytes
        nonce = reader.read(8)

        payload_header_length_key = kdf16(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_length_nonce = kdf12(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                encrypted_auth_id,
                nonce,
            ],
        )
        header_length_bytes = AESGCM(payload_header_length_key).decrypt(
            payload_header_length_nonce, encrypted_header_length, encrypted_auth_id
        )
        length = int.from_bytes(header_length_bytes, "big")

        encrypted_payload_header = reader.read(length + 16)  # AEAD tag size is 16 bytes
        payload_header_key = kdf16(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_KEY,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_nonce = kdf12(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_IV,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_bytes = AESGCM(payload_header_key).decrypt(
            payload_header_nonce, encrypted_payload_header, encrypted_auth_id
        )
        payload = VMessPlainPacketHeader.from_packet(
            payload_header_bytes, verify_checksum
        )
        return cls(auth_id, length, nonce, payload, reader.offset)

    def read_body(self, reader: BaseReader, verify_checksum: bool = True):
        # TODO: move this function to separate class
        masker = None
        if self.payload.options & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Stream(self.payload.body_iv)

        for count in itertools.count():
            # TODO: add check if not using chunked data
            if (
                self.payload.options & VMessBodyOptions.GLOBAL_PADDING
                and masker is not None
            ):
                padding_length = masker.next_uint16() % 64
            else:
                padding_length = 0

            aead_nonce = count.to_bytes(2, "big") + self.payload.body_iv[2:12]
            if self.payload.options & VMessBodyOptions.AUTHENTICATED_LENGTH:
                key = kdf16(self.payload.body_key, [b"auth_len"])
                if self.payload.security is VMessBodySecurity.AES_128_GCM:
                    cipher = AESGCM(key)
                elif self.payload.security is VMessBodySecurity.CHACHA20_POLY1305:
                    cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(key))
                else:
                    raise ValueError(
                        f"Authenticated length is not supported for {self.payload.security!r}"
                    )
                encrypted_length = reader.read(2 + 16)  # AEAD tag size is 16 bytes
                decrypted_length = cipher.decrypt(aead_nonce, encrypted_length, None)
                length = int.from_bytes(decrypted_length, "big") + 16
            elif masker is not None:
                length = reader.read_uint16() ^ masker.next_uint16()
            else:
                length = reader.read_uint16()

            content_length = length - padding_length

            if self.payload.security is VMessBodySecurity.NONE:
                yield reader.read(content_length)
            elif self.payload.security is VMessBodySecurity.AES_128_CFB:
                decryptor = Cipher(
                    algorithms.AES(self.payload.body_key),
                    modes.CFB(self.payload.body_iv),
                ).decryptor()
                encrypted_data = reader.read(content_length - 4)  # 4 bytes for checksum
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                checksum = reader.read_uint32()
                if verify_checksum:
                    assert checksum == fnv1a32(decrypted_data)
                yield decrypted_data
            elif self.payload.security is VMessBodySecurity.AES_128_GCM:
                cipher = AESGCM(self.payload.body_key)
                encrypted_data = reader.read(content_length)
                yield cipher.decrypt(aead_nonce, encrypted_data, None)
            elif self.payload.security is VMessBodySecurity.CHACHA20_POLY1305:
                cipher = ChaCha20Poly1305(
                    generate_chacha20_poly1305_key(self.payload.body_key)
                )
                encrypted_data = reader.read(content_length)
                yield cipher.decrypt(aead_nonce, encrypted_data, None)
            else:
                raise ValueError(f"Unknown security: {self.payload.security!r}")

            if padding_length > 0:
                reader.read(padding_length)
            count += 1
        return
