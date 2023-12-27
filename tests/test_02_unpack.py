import uuid
from io import BytesIO
from ipaddress import IPv4Address
from pathlib import Path

from vmess_aead import VMessAEADRequestPacketHeader, VMessBodyEncoder
from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.headers.request import VMessAuthID, VMessPlainPacketHeader
from vmess_aead.utils.reader import BufferedReader, IOReader


def test_full_header():
    user_id = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")

    data = bytes.fromhex(
        (Path(__file__).parent / "resources" / "captured.hex").read_text()
    )
    reader = BufferedReader(IOReader(BytesIO(data)))

    header = VMessAEADRequestPacketHeader.from_packet(
        reader, user_id, timestamp=1703242500
    )
    header_compare = VMessAEADRequestPacketHeader(
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
    assert header == header_compare
    encoder = VMessBodyEncoder(
        header.payload.body_key,
        header.payload.body_iv,
        header.payload.options,
        header.payload.security,
        header.payload.command,
    )
    body = encoder.decode_once(reader)
    assert (
        body
        == b"GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    )
