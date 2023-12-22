import binascii
import uuid
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.reader import StatefulReader
from vmess_aead.utils import cmd_key, fnv1a32


@dataclass
class VMessAuthID:
    timestamp: int
    """Timestamp in seconds, uint64, big endian"""
    rand: bytes
    """Random bytes, 4 bytes"""

    @classmethod
    def from_encrypted(
        cls, encrypted: bytes, uuid: uuid.UUID, verify_checksum: bool = True
    ):
        decrypted = cls._decrypt(
            encrypted, kdf16(cmd_key(uuid), [KDFSaltConst.AUTH_ID_ENCRYPTION_KEY])
        )
        reader = StatefulReader(decrypted)
        timestamp = reader.read_uint64()
        rand = reader.read(4)
        checksum_body = reader.read_all_before()
        checksum = reader.read_uint32()
        if verify_checksum:
            assert checksum == binascii.crc32(checksum_body)
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
    def read(cls, packet: bytes, verify_checksum: bool = True):
        reader = StatefulReader(packet)
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
        checksum_body = reader.read_all_before()
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
class VMessAEADPacketHeader:
    auth_id: VMessAuthID
    """Authentication ID"""
    length: int
    """Length of the payload, uint16, big endian"""
    nonce: bytes
    """Nonce, 8 bytes"""
    payload: VMessPlainPacketHeader
    """Payload"""

    @classmethod
    def read(
        cls,
        packet: bytes,
        uuid: uuid.UUID,
        *,
        verify_checksum: bool = True,
        timestamp: Optional[int] = None,
        timestamp_range: int = 2 * 60,
    ):
        reader = StatefulReader(packet)
        encrypted_auth_id = reader.read(16)
        auth_id = VMessAuthID.from_encrypted(encrypted_auth_id, uuid, verify_checksum)
        if timestamp is not None:
            assert abs(timestamp - auth_id.timestamp) <= timestamp_range

        encrypted_header_length = reader.read(2 + 16)  # AEAD tag size is 16 bytes
        nonce = reader.read(8)

        payload_header_length_key = kdf16(
            cmd_key(uuid),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_length_nonce = kdf12(
            cmd_key(uuid),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                encrypted_auth_id,
                nonce,
            ],
        )
        header_length_bytes = cls._gcm_decrypt(
            payload_header_length_key,
            payload_header_length_nonce,
            encrypted_header_length,
            encrypted_auth_id,
        )
        length = int.from_bytes(header_length_bytes, "big")

        encrypted_payload_header = reader.read(length + 16)  # AEAD tag size is 16 bytes
        payload_header_key = kdf16(
            cmd_key(uuid),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_KEY,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_nonce = kdf12(
            cmd_key(uuid),
            [
                KDFSaltConst.VMESS_HEADER_PAYLOAD_AEAD_IV,
                encrypted_auth_id,
                nonce,
            ],
        )
        payload_header_bytes = cls._gcm_decrypt(
            payload_header_key,
            payload_header_nonce,
            encrypted_payload_header,
            encrypted_auth_id,
        )
        payload = VMessPlainPacketHeader.read(payload_header_bytes, verify_checksum)
        return cls(auth_id, length, nonce, payload)

    @staticmethod
    def _gcm_decrypt(key: bytes, nonce: bytes, cipher_text: bytes, ad: bytes) -> bytes:
        aes_gcm = AESGCM(key)
        return aes_gcm.decrypt(nonce, cipher_text, ad)