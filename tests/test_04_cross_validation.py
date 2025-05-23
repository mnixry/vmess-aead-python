import itertools
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

from vmess_aead.encoding import VMessBodyDecoder, VMessBodyEncoder
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
from vmess_aead.utils import generate_response_key
from vmess_aead.utils.reader import IOReader

if platform.system() != "Linux" or platform.machine() != "x86_64":
    pytest.skip("Cross validation only works on Linux x86_64", allow_module_level=True)


RESOURCES_DIR = Path(__file__).parent / "resources"


def bitmask_combination(
    *enums: VMessBodyOptions,
    extra: VMessBodyOptions = VMessBodyOptions(0),
):
    return {
        VMessBodyOptions(sum(x) | extra)
        for i in range(len(enums) + 1)
        for x in itertools.combinations(enums, i)
    }


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
    for _ in range(10):  # pragma: no branch
        try:
            sock.connect(("localhost", 10086))
            break
        except Exception:  # pragma: no cover
            time.sleep(0.5)
    sock.close()

    yield process
    process.terminate()
    return


@pytest.mark.parametrize(
    "options",
    bitmask_combination(
        VMessBodyOptions.CHUNK_MASKING,
        VMessBodyOptions.GLOBAL_PADDING,
        VMessBodyOptions.AUTHENTICATED_LENGTH,
        VMessBodyOptions.CHUNK_STREAM,
    ),
    ids=lambda x: x.name,
)
@pytest.mark.parametrize(
    "security",
    [
        VMessBodySecurity.AES_128_CFB,
        VMessBodySecurity.AES_128_GCM,
        VMessBodySecurity.CHACHA20_POLY1305,
        VMessBodySecurity.NONE,
    ],
    ids=lambda x: x.name,
)
def test_as_client(
    v2ray_server: subprocess.Popen,
    options: VMessBodyOptions,
    security: VMessBodySecurity,
):
    client = socket.socket()
    client.connect(("localhost", 10086))
    client.settimeout(5)

    server = socket.socket()
    server.bind(("localhost", 0))
    server.listen(1)
    server.settimeout(2)

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

    if (
        options & VMessBodyOptions.GLOBAL_PADDING
        and not options & VMessBodyOptions.CHUNK_MASKING
    ):
        with pytest.raises(socket.timeout):
            server_connection, addr = server.accept()
        return
    else:
        server_connection, addr = server.accept()
    server_connection.settimeout(5)
    server_connection.send(b"ok")

    reader = IOReader(client.makefile("rb"))

    # socket file is not seekable
    with pytest.raises(NotImplementedError):
        assert reader.remaining

    resp_iv = generate_response_key(header_packet.payload.body_iv)
    resp_key = generate_response_key(header_packet.payload.body_key)
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

    recv_encoder = VMessBodyDecoder(
        body_key=resp_key,
        body_iv=resp_iv,
        options=header_packet.payload.options,
        security=header_packet.payload.security,
        command=header_packet.payload.command,
        authenticated_length_iv=header_packet.payload.body_iv,
        authenticated_length_key=header_packet.payload.body_key,
    )

    data_sent = b"ok"
    for _ in range(10):
        data = token_bytes(randbits(12))
        server_connection.sendall(data)
        data_sent += data

    data_recv = b""
    while True:
        chunks = recv_encoder.decode(reader.read(1))
        data_recv += b"".join(chunks)
        if len(data_recv) >= len(data_sent):
            break
    assert data_recv == data_sent


@pytest.mark.skip("TODO")
def test_as_server():
    pass
