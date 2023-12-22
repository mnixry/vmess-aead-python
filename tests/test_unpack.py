import uuid
from ipaddress import IPv4Address
from pathlib import Path

from vmess_aead import VMessAEADRequestPacketHeader
from vmess_aead.kdf import kdf


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
    data = bytes.fromhex(Path(__file__).parent.joinpath("test.hex").read_text())
    user_id = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    read = VMessAEADRequestPacketHeader.read(data, user_id, timestamp=1703242500)

    assert read.payload.address == IPv4Address("104.26.12.31")
    assert read.payload.port == 80
    body = [*read.read_body(data[read.read_offset :])]
    assert body == [
        b"GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    ]


if __name__ == "__main__":
    test_kdf()
    test_full_header()
