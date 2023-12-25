import uuid
from io import BytesIO
from ipaddress import IPv4Address
from pathlib import Path

from vmess_aead import VMessAEADRequestPacketHeader
from vmess_aead.kdf import kdf
from vmess_aead.utils.reader import BufferedReader, IOReader


def test_kdf():
    derived_key = kdf(
        b"Demo Key for KDF Value Test",
        [
            b"Demo Path for KDF Value Test",
            b"Demo Path for KDF Value Test2",
            b"Demo Path for KDF Value Test3",
        ],
    )
    assert derived_key == bytes.fromhex(
        "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
    ), "should generate correct key"


def test_full_header():
    user_id = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")

    data = bytes.fromhex((Path(__file__).parent / "test.hex").read_text())
    reader = BufferedReader(IOReader(BytesIO(data)))

    header = VMessAEADRequestPacketHeader.from_packet(
        reader, user_id, timestamp=1703242500
    )
    assert header.payload.address == IPv4Address("104.26.12.31")
    assert header.payload.port == 80
    body = next(header.read_body(reader))
    assert (
        body
        == b"GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    )


if __name__ == "__main__":
    test_kdf()
    test_full_header()
