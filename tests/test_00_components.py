import socket
from io import BytesIO

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from vmess_aead.kdf import kdf
from vmess_aead.utils import SM4GCM
from vmess_aead.utils.reader import (
    BufferedReader,
    BytesReader,
    IOReader,
    ReadOutOfBoundError,
    SocketReader,
    StreamCipherReader,
)


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


def test_bytes_reader():
    reader = BytesReader(b"12345")
    reader.append(b"67890")
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read_before() == b"12345"
    assert reader.read_all() == b"67890"
    assert reader.offset == 10
    assert reader.remaining == 0

    with pytest.raises(ReadOutOfBoundError):
        reader.read(5)


def test_buffered_reader():
    reader = BufferedReader(BytesReader(b"1234567890"))
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read_before() == b"12345"
    assert reader.read_all() == b"67890"
    assert reader.offset == 10

    with pytest.raises(ReadOutOfBoundError):
        reader.read(5)


def test_io_reader():
    reader = IOReader(BytesIO(b"1234567890"))
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read_all() == b"67890"
    assert reader.offset == 10

    with pytest.raises(ReadOutOfBoundError):
        reader.read(5)


def test_stream_cipher_reader():
    key = b"1234567890123456"
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    reader = StreamCipherReader(
        BytesReader(bytes.fromhex("444efe38e96aa7d2e2de")), cipher
    )
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read_until(b"8") == b"678"
    assert reader.read_all() == b"90"
    assert reader.offset == 10

    with pytest.raises(ReadOutOfBoundError):
        reader.read(5)


def test_socket_reader():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 0))
    server.listen()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server.getsockname())
    client.send(b"1234567890")
    client.close()

    connection, src_addr = server.accept()
    reader = SocketReader(connection)
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read(5) == b"67890"
    assert reader.offset == 10

    with pytest.raises(ReadOutOfBoundError):
        reader.read(5)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server.getsockname())
    client.send(b"1234567890")
    client.close()

    connection, src_addr = server.accept()
    reader = SocketReader(connection, buffer_size=2)
    assert reader.read(5) == b"12345"
    assert reader.offset == 5
    assert reader.read_all() == b"67890"
    assert reader.offset == 10


def test_sm4_gcm():
    # test vector from https://tools.ietf.org/html/rfc8998#appendix-A.1
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    nonce = bytes.fromhex("00001234567800000000ABCD")
    associated_data = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
    plain_text = bytes.fromhex(
        "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
        "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
        "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
    )
    cipher_text = bytes.fromhex(
        "17F399F08C67D5EE19D0DC9969C4BB7D"
        "5FD46FD3756489069157B282BB200735"
        "D82710CA5C22F0CCFA7CBF93D496AC15"
        "A56834CBCF98C397B4024A2691233B8D"
    )
    tag = bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC")

    sm4gcm = SM4GCM(key)
    assert sm4gcm.encrypt(nonce, plain_text, associated_data) == cipher_text + tag
    assert sm4gcm.decrypt(nonce, cipher_text, associated_data, tag) == plain_text
