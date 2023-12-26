import uuid
from ipaddress import IPv4Address
from pathlib import Path

from vmess_aead import VMessAEADRequestPacketHeader
from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.headers.request import VMessAuthID, VMessPlainPacketHeader


def test_pack():
    user_id = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    packet = b""

    header = VMessAEADRequestPacketHeader(
        auth_id=VMessAuthID(timestamp=1703242529, rand=b"*0\x8d\x1a"),
        nonce=b"\xc7\x7f\xd3\xc0\xec\xe0\x85*",
        payload=VMessPlainPacketHeader(
            version=1,
            body_iv=b"\xb0\xe07.\xd1\xbe\xcf)\x88\xcd\xbfY-)\xa3t",
            body_key=b"\xecQ\x90#\x1a\xc5\xe5\x88\xc3\x8d\xcaMw\x00\xa0L",
            response_header=120,
            options=(
                VMessBodyOptions.CHUNK_MASKING
                | VMessBodyOptions.CHUNK_STREAM
                | VMessBodyOptions.GLOBAL_PADDING
            ),
            padding_length=0,
            security=VMessBodySecurity.AES_128_GCM,
            reserved=0,
            command=VMessBodyCommand.TCP,
            port=80,
            address_type=VMessBodyAddressType.IPV4,
            address=IPv4Address("104.26.12.31"),
            padding=b"",
        ),
    )
    packet += header.to_packet(user_id)

    encoder = VMessBodyEncoder(
        header.payload.body_key,
        header.payload.body_iv,
        header.payload.options,
        header.payload.security,
        header.payload.command,
    )

    def pseudo_padding(length: int):
        assert length == 37
        return bytes.fromhex(
            "36bdd3be6fb863c0b9c9907283c47d6d"
            "d54e637ff99408ac1ea9dc3600d3b106"
            "2fdcd04714"
        )

    packet += encoder.encode(
        b"GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
        padding_generator=pseudo_padding,
    )

    with (Path(__file__).parent / "test.hex").open("rt") as f:
        assert bytes.fromhex(f.read()) == packet
