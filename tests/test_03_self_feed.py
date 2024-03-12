import itertools
import time
from ipaddress import IPv4Address, IPv6Address
from secrets import randbits, token_bytes
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
from vmess_aead.utils import generate_response_key
from vmess_aead.utils.reader import BytesReader


def bitmask_combination(*enums: VMessBodyOptions):
    return {
        VMessBodyOptions(sum(x))
        for i in range(len(enums) + 1)
        for x in itertools.combinations(enums, i)
    }


@pytest.mark.parametrize(
    "options",
    [
        opt
        for opt in bitmask_combination(
            VMessBodyOptions.CHUNK_STREAM,
            VMessBodyOptions.CHUNK_MASKING,
            VMessBodyOptions.GLOBAL_PADDING,
            VMessBodyOptions.AUTHENTICATED_LENGTH,
        )
        if not (
            opt & VMessBodyOptions.GLOBAL_PADDING
            and not opt & VMessBodyOptions.CHUNK_MASKING
        )
    ],
    ids=lambda x: x.name,
)
@pytest.mark.parametrize("security", [*VMessBodySecurity], ids=lambda x: x.name)
@pytest.mark.parametrize("command", [*VMessBodyCommand], ids=lambda x: x.name)
@pytest.mark.parametrize(
    "address_type, address",
    [
        (VMessBodyAddressType.IPV4, IPv4Address("1.1.1.1")),
        (VMessBodyAddressType.DOMAIN, "example.com"),
        (VMessBodyAddressType.IPV6, IPv6Address("::1")),
    ],
    ids=lambda x: x.name if isinstance(x, VMessBodyAddressType) else type(x).__name__,
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
    ids=lambda x: type(x).__name__ if x is not None else None,
)
def test_feed(
    options: VMessBodyOptions,
    security: VMessBodySecurity,
    command: VMessBodyCommand,
    address_type: VMessBodyAddressType,
    address: IPv4Address,
    resp_command: VMessResponseCommandSwitchAccount | None,
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
    resp_body_key = generate_response_key(header.payload.body_key)
    resp_body_iv = generate_response_key(header.payload.body_iv)
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
