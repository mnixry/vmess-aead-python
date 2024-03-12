from binascii import crc32
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.utils import cmd_key, fnv1a32
from vmess_aead.utils.reader import BaseReader, BytesReader


@dataclass
class VMessAuthID:
    timestamp: int
    """Timestamp in seconds, uint64, big endian"""
    rand: bytes
    """Random bytes, 4 bytes"""

    @classmethod
    def from_packet(cls, encrypted: bytes, user_id: UUID, verify_checksum: bool = True):
        key = kdf16(cmd_key(user_id), [KDFSaltConst.AUTH_ID_ENCRYPTION_KEY])
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        reader = BytesReader(decryptor.update(encrypted) + decryptor.finalize())
        timestamp = reader.read_uint64()
        rand = reader.read(4)
        checksum_body = reader.read_before()
        checksum = reader.read_uint32()
        if verify_checksum and checksum != crc32(checksum_body):
            raise ValueError("Checksum mismatch")  # pragma: no cover
        return cls(timestamp, rand)

    def to_packet(self, user_id: UUID):
        plain_packet = b""
        plain_packet += self.timestamp.to_bytes(8, "big")
        plain_packet += self.rand
        checksum = crc32(plain_packet)
        plain_packet += checksum.to_bytes(4, "big")
        key = kdf16(cmd_key(user_id), [KDFSaltConst.AUTH_ID_ENCRYPTION_KEY])
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plain_packet) + encryptor.finalize()
        return encrypted


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
    address: IPv4Address | IPv6Address | str
    """Address, variable length"""
    padding: bytes
    """Padding bytes, variable length"""

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
        match address_type:
            case VMessBodyAddressType.IPV4:
                address = IPv4Address(reader.read_uint32())
            case VMessBodyAddressType.DOMAIN:
                address = reader.read(reader.read_byte()).decode()
            case VMessBodyAddressType.IPV6:
                address = IPv6Address(reader.read_uint128())
            case _:  # pragma: no cover
                raise ValueError(f"Unknown {address_type=}")
        padding = b""
        if padding_length > 0:
            padding = reader.read(padding_length)
        checksum_body = reader.read_before()
        checksum = reader.read_uint32()
        if verify_checksum and checksum != fnv1a32(checksum_body):
            raise ValueError("Checksum mismatch")  # pragma: no cover
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
            padding,
        )

    def to_packet(self):
        packet = b""
        packet += self.version.to_bytes(1, "big")
        packet += self.body_iv
        packet += self.body_key
        packet += self.response_header.to_bytes(1, "big")
        packet += self.options.value.to_bytes(1, "big")
        packet += ((self.padding_length << 4) | self.security.value).to_bytes(1, "big")
        packet += self.reserved.to_bytes(1, "big")
        packet += self.command.value.to_bytes(1, "big")
        packet += self.port.to_bytes(2, "big")
        packet += self.address_type.value.to_bytes(1, "big")
        match self.address:
            case IPv4Address(packed=packed) | IPv6Address(packed=packed):
                packet += packed
            case _:
                address_bytes = self.address.encode()
                packet += len(address_bytes).to_bytes(1, "big")
                packet += address_bytes
        if self.padding_length > 0:
            packet += self.padding
        checksum = fnv1a32(packet)
        packet += checksum.to_bytes(4, "big")
        return packet


@dataclass
class VMessAEADRequestPacketHeader:
    """Packet send from client to server"""

    auth_id: VMessAuthID
    """Authentication ID"""
    nonce: bytes
    """Nonce, 8 bytes"""
    payload: VMessPlainPacketHeader
    """Payload"""

    @classmethod
    def from_packet(
        cls,
        reader: BaseReader,
        user_id: UUID,
        *,
        verify_checksum: bool = True,
        timestamp: int | None = None,
        timestamp_range: int = 2 * 60,
    ):
        encrypted_auth_id = reader.read(16)
        auth_id = VMessAuthID.from_packet(encrypted_auth_id, user_id, verify_checksum)
        if (
            timestamp is not None
            and abs(timestamp - auth_id.timestamp) > timestamp_range
        ):
            raise ValueError("Timestamp mismatch")  # pragma: no cover
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
        return cls(auth_id, nonce, payload)

    def to_packet(self, user_id: UUID):
        packet = b""
        packet += (encrypted_auth_id := self.auth_id.to_packet(user_id))
        assert len(encrypted_auth_id) == 16 and len(self.nonce) == 8

        payload_header_key = kdf16(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_KEY,
                encrypted_auth_id,
                self.nonce,
            ],
        )
        payload_header_nonce = kdf12(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_IV,
                encrypted_auth_id,
                self.nonce,
            ],
        )
        encrypted_payload = AESGCM(payload_header_key).encrypt(
            payload_header_nonce, self.payload.to_packet(), encrypted_auth_id
        )

        payload_header_length_key = kdf16(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                encrypted_auth_id,
                self.nonce,
            ],
        )
        payload_header_length_nonce = kdf12(
            cmd_key(user_id),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                encrypted_auth_id,
                self.nonce,
            ],
        )
        packet += AESGCM(payload_header_length_key).encrypt(
            payload_header_length_nonce,
            (len(encrypted_payload) - 16).to_bytes(2, "big"),
            encrypted_auth_id,
        )
        packet += self.nonce
        packet += encrypted_payload
        return packet
