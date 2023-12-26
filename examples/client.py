import hashlib
import socket
import time
import uuid
from secrets import token_bytes

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

s = socket.socket()
s.connect(("localhost", 10086))

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
        response_header=token_bytes(1)[0],
        options=VMessBodyOptions.CHUNK_MASKING
        | VMessBodyOptions.CHUNK_STREAM
        | VMessBodyOptions.GLOBAL_PADDING
        | VMessBodyOptions.AUTHENTICATED_LENGTH,
        padding_length=10,
        security=VMessBodySecurity.AES_128_GCM,
        reserved=0,
        command=VMessBodyCommand.TCP,
        address="localhost",
        port=8000,
        address_type=VMessBodyAddressType.DOMAIN,
        padding=token_bytes(10),
    ),
)

s.sendall(
    p1 := header_packet.to_packet(
        user_id=uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    )
)
print(p1.hex())

send_encoder = VMessBodyEncoder(
    body_key=header_packet.payload.body_key,
    body_iv=header_packet.payload.body_iv,
    options=header_packet.payload.options,
    security=header_packet.payload.security,
    command=header_packet.payload.command,
)
s.sendall(
    p2 := send_encoder.encode(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    )
)
print(p2.hex())


reader = SocketReader(s)

resp_header = VMessAEADResponsePacketHeader.from_packet(
    reader,
    body_iv=(resp_iv := hashlib.sha256(header_packet.payload.body_iv).digest()[0:16]),
    body_key=(
        resp_key := hashlib.sha256(header_packet.payload.body_key).digest()[0:16]
    ),
)
resp_encoder = VMessBodyEncoder(
    body_key=resp_key,
    body_iv=resp_iv,
    options=header_packet.payload.options,
    security=header_packet.payload.security,
    authenticated_length_iv=header_packet.payload.body_iv,
    authenticated_length_key=header_packet.payload.body_key,
    command=header_packet.payload.command,
)


print(resp_header)
print(resp_encoder.decode_once(reader))
