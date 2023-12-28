import hashlib
import platform
import socket
import subprocess
import time
import uuid
from pathlib import Path
from secrets import randbits, token_bytes
from shutil import unpack_archive
from tempfile import TemporaryDirectory, mktemp
from urllib.request import urlretrieve

import pytest

from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import (
    VMessBodyAddressType,
    VMessBodyCommand,
    VMessBodyOptions,
    VMessBodySecurity,
)
from vmess_aead.headers.request import (
    VMessAEADRequestPacketHeader,
    VMessAuthID,
    VMessPlainPacketHeader,
)
from vmess_aead.headers.response import VMessAEADResponsePacketHeader
from vmess_aead.utils.reader import SocketReader

if platform.system() != "Linux" or platform.machine() != "x86_64":
    pytest.skip("Cross validation only works on Linux x86_64", allow_module_level=True)


RESOURCES_DIR = Path(__file__).parent / "resources"


@pytest.fixture(scope="module")
def v2ray_core():
    url = "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip"
    with TemporaryDirectory(dir=RESOURCES_DIR) as tmpdir:
        filename = mktemp(dir=tmpdir, suffix=".zip")
        urlretrieve(url, filename)
        unpack_archive(filename, extract_dir=tmpdir)
        executable = Path(tmpdir) / "v2ray"
        executable.chmod(0o755)
        yield executable


@pytest.fixture(scope="module")
def v2ray_server(v2ray_core: Path):
    server_config = RESOURCES_DIR / "config.server.json"
    process = subprocess.Popen([v2ray_core, "run", "-c", server_config])

    sock = socket.socket()
    sock.settimeout(5)
    # Wait for server to start
    for _ in range(10):
        try:
            sock.connect(("localhost", 10086))
            break
        except Exception:
            time.sleep(0.5)
    sock.close()

    yield process
    process.terminate()
    return


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
    ids=lambda x: x.name,
)
@pytest.mark.parametrize("security", [*VMessBodySecurity], ids=lambda x: x.name)
def test_as_client(
    v2ray_server: subprocess.Popen,
    options: VMessBodyOptions,
    security: VMessBodySecurity,
):
    client = socket.socket()
    client.connect(("localhost", 10086))

    server = socket.socket()
    server.bind(("localhost", 0))
    server.listen(10)
    _, port = server.getsockname()

    header_packet = VMessAEADRequestPacketHeader(
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
            command=VMessBodyCommand.TCP,
            address="localhost",
            port=port,
            address_type=VMessBodyAddressType.DOMAIN,
            padding=token_bytes(padding_length),
        ),
    )

    client.sendall(
        header_packet.to_packet(
            user_id=uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
        )
    )

    server_connection, addr = server.accept()
    server_connection.sendall(b"ok")
    server_connection.settimeout(5)

    reader = SocketReader(client)
    resp_iv = hashlib.sha256(header_packet.payload.body_iv).digest()[0:16]
    resp_key = hashlib.sha256(header_packet.payload.body_key).digest()[0:16]
    resp_header = VMessAEADResponsePacketHeader.from_packet(
        reader, body_iv=resp_iv, body_key=resp_key
    )

    assert resp_header.response_header == header_packet.payload.response_header

    send_encoder = VMessBodyEncoder(
        body_key=header_packet.payload.body_key,
        body_iv=header_packet.payload.body_iv,
        options=header_packet.payload.options,
        security=header_packet.payload.security,
        command=header_packet.payload.command,
    )

    for r in range(10):
        data = token_bytes(randbits(12))
        client.sendall(send_encoder.encode(data))
        recv_data = b""
        while len(recv_data) < len(data):
            recv_data += server_connection.recv(1024)
        assert recv_data == data, f"Round {r} failed"

    recv_encoder = VMessBodyEncoder(
        body_key=resp_key,
        body_iv=resp_iv,
        options=header_packet.payload.options,
        security=header_packet.payload.security,
        command=header_packet.payload.command,
        authenticated_length_iv=header_packet.payload.body_iv,
        authenticated_length_key=header_packet.payload.body_key,
    )

    assert recv_encoder.decode_once(reader) == b"ok"

    for r in range(10):
        data = token_bytes(randbits(12))
        server_connection.sendall(data)
        recv_data = b""
        while len(recv_data) < len(data):
            recv_data += recv_encoder.decode_once(reader)
        assert recv_data == data, f"Round {r} failed"


def test_as_server():
    # TODO
    pass
