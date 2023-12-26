import hashlib
import time
from ipaddress import IPv4Address, IPv6Address
from secrets import randbits, token_bytes
from typing import Optional
from uuid import uuid4

import pytest
from vmess_aead import VMessAEADRequestPacketHeader, VMessAEADResponsePacketHeader
from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
    VMessResponseBodyOptions,
)
from vmess_aead.headers.request import VMessAuthID, VMessPlainPacketHeader
from vmess_aead.headers.response import VMessResponseCommandSwitchAccount
from vmess_aead.utils.reader import BytesReader


@pytest.mark.parametrize(
    "options",
    [
        VMessBodyOptions.CHUNK_STREAM,
        VMessBodyOptions.CHUNK_STREAM | VMessBodyOptions.CHUNK_MASKING,
        VMessBodyOptions.CHUNK_STREAM
        | VMessBodyOptions.CHUNK_MASKING
        | VMessBodyOptions.GLOBAL_PADDING,
        VMessBodyOptions.CHUNK_STREAM
        | VMessBodyOptions.CHUNK_MASKING
        | VMessBodyOptions.AUTHENTICATED_LENGTH,
        VMessBodyOptions.CHUNK_STREAM
        | VMessBodyOptions.CHUNK_MASKING
        | VMessBodyOptions.AUTHENTICATED_LENGTH
        | VMessBodyOptions.GLOBAL_PADDING,
    ],
)
@pytest.mark.parametrize("security", [*VMessBodySecurity])
@pytest.mark.parametrize("command", [*VMessBodyCommand])
@pytest.mark.parametrize(
    "address_type, address",
    [
        (VMessBodyAddressType.IPV4, IPv4Address("1.1.1.1")),
        (VMessBodyAddressType.DOMAIN, "example.com"),
        (VMessBodyAddressType.IPV6, IPv6Address("::1")),
    ],
)
@pytest.mark.parametrize(
    "resp_command",
    [
        None,
        VMessResponseCommandSwitchAccount(
            command_id=0x01,
            host="",
            port=11451,
            id_=uuid4(),
            alter_ids=0,
            level=4,
            valid_minutes=32,
        ),
    ],
)
def test_feed(
    options: VMessBodyOptions,
    security: VMessBodySecurity,
    command: VMessBodyCommand,
    address_type: VMessBodyAddressType,
    address: IPv4Address,
    resp_command: Optional[VMessResponseCommandSwitchAccount],
):
    user_id = uuid4()
    header = VMessAEADRequestPacketHeader(
        auth_id=VMessAuthID(
            timestamp=int(time.time()),
            rand=token_bytes(4),
        ),
        nonce=token_bytes(8),
        payload=VMessPlainPacketHeader(
            version=1,
            body_iv=token_bytes(16),
            body_key=token_bytes(16),
            response_header=randbits(8),
            options=options,
            padding_length=(padding_length := randbits(4)),
            security=security,
            reserved=0,
            command=command,
            port=randbits(16),
            address_type=address_type,
            address=address,
            padding=token_bytes(padding_length),
        ),
    )
    packet = header.to_packet(user_id)

    assert (
        VMessAEADRequestPacketHeader.from_packet(BytesReader(packet), user_id) == header
    )

    resp_header = VMessAEADResponsePacketHeader(
        response_header=header.payload.response_header,
        options=VMessResponseBodyOptions(0),
        command=resp_command,
    )
    resp_body_key = hashlib.sha256(header.payload.body_key).digest()[0:16]
    resp_body_iv = hashlib.sha256(header.payload.body_iv).digest()[0:16]
    resp_packet = resp_header.to_packet(resp_body_key, resp_body_iv)

    assert (
        VMessAEADResponsePacketHeader.from_packet(
            BytesReader(resp_packet), resp_body_key, resp_body_iv
        )
        == resp_header
    )

    encoder = VMessBodyEncoder(
        body_key=resp_body_key,
        body_iv=resp_body_iv,
        security=security,
        command=command,
        options=options,
        authenticated_length_iv=header.payload.body_iv,
        authenticated_length_key=header.payload.body_key,
    )

    decoder = VMessBodyEncoder(
        body_key=resp_body_key,
        body_iv=resp_body_iv,
        security=security,
        command=command,
        options=options,
        authenticated_length_iv=header.payload.body_iv,
        authenticated_length_key=header.payload.body_key,
    )

    for _ in range(10):
        body = token_bytes(randbits(12))
        encoded_body = encoder.encode(body)
        decoded_body = decoder.decode_once(BytesReader(encoded_body))
        assert body == decoded_body
