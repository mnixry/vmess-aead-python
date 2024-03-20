import asyncio
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from secrets import randbelow, token_bytes
from typing import Self

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
from vmess_aead.utils import generate_response_key
from vmess_aead.utils.reader import BytesReader, ReadOutOfBoundError

logger = logging.getLogger(__name__)

_MAX_PACKET_SIZE = 0x8000  # 32KB


@dataclass(frozen=True)
class VMessClientConfig:
    server_host: str
    server_port: int

    user_id: uuid.UUID
    security: VMessBodySecurity = VMessBodySecurity.AES_128_GCM
    options: VMessBodyOptions = (
        VMessBodyOptions.CHUNK_MASKING
        | VMessBodyOptions.CHUNK_STREAM
        | VMessBodyOptions.GLOBAL_PADDING
    )
    timeout: float = 60


class VMessClientProtocol(asyncio.Protocol):
    header: VMessAEADRequestPacketHeader | None = None
    resp_header: VMessAEADResponsePacketHeader | None = None

    def __init__(
        self,
        host: str | IPv4Address | IPv6Address,
        port: int,
        connection_type: VMessBodyCommand,
        *,
        config: VMessClientConfig,
    ) -> None:
        self.host, self.port = host, port
        self.connection_type = connection_type

        self.user_id = config.user_id
        self.security = config.security
        self.options = config.options
        self.timeout = config.timeout

        self.reader = BytesReader(b"")
        self.bytes_received = 0
        self.bytes_sent = 0
        self.send_queue = deque[bytes]()

        loop = asyncio.get_running_loop()
        loop.call_later(self.timeout, self._timeout_check)
        self.connection_event: asyncio.Future[Self] = loop.create_future()
        self.data_received_event = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport

        logger.info(
            "Connection established to remote server %s:%s",
            *transport.get_extra_info("peername"),
        )

        body_key, body_iv = token_bytes(16), token_bytes(16)
        response_header = randbelow(0xFF)
        padding = token_bytes(padding_length := randbelow(0xF))

        match self.host:
            case IPv4Address():
                address_type = VMessBodyAddressType.IPV4
            case IPv6Address():
                address_type = VMessBodyAddressType.IPV6
            case str():
                address_type = VMessBodyAddressType.DOMAIN
            case _:  # pragma: no cover
                raise ValueError("Invalid host type")

        self.header = VMessAEADRequestPacketHeader(
            auth_id=VMessAuthID(
                timestamp=int(time.time()),
                rand=token_bytes(4),
            ),
            nonce=token_bytes(8),
            payload=VMessPlainPacketHeader(
                version=1,
                body_iv=body_iv,
                body_key=body_key,
                response_header=response_header,
                options=self.options,
                padding_length=padding_length,
                security=self.security,
                reserved=0,
                command=self.connection_type,
                address=self.host,
                port=self.port,
                address_type=address_type,
                padding=padding,
            ),
        )
        self.encoder = VMessBodyEncoder(
            body_key,
            body_iv,
            self.options,
            self.security,
            self.connection_type,
        )
        self.transport.write(self.header.to_packet(user_id=self.user_id))

        resp_key = generate_response_key(self.header.payload.body_key)
        resp_iv = generate_response_key(self.header.payload.body_iv)
        self.resp_encoder = VMessBodyEncoder(
            resp_key,
            resp_iv,
            self.header.payload.options,
            self.header.payload.security,
            self.header.payload.command,
            authenticated_length_iv=self.header.payload.body_iv,
            authenticated_length_key=self.header.payload.body_key,
        )

        while self.send_queue:
            self.send_data(self.send_queue.popleft())

    def _timeout_check(self):
        if self.resp_header is not None:
            return
        logger.error("Timeout %d seconds reached before response", self.timeout)
        self.connection_event.set_exception(asyncio.TimeoutError)
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        self.bytes_received += (data_length := len(data))
        logger.debug("%d bytes received from remote server", data_length)
        self.reader.append(data)

        if self.resp_header is None:
            self._initialize_resp_header()

        if self.reader.remaining and not self.data_received_event.is_set():
            self.data_received_event.set()

    def _initialize_resp_header(self):
        assert self.header is not None

        self.resp_header = VMessAEADResponsePacketHeader.from_packet(
            self.reader,
            body_iv=self.resp_encoder.body_iv,
            body_key=self.resp_encoder.body_key,
        )
        if self.resp_header.command is not None:
            logger.error(
                "Unexpected command in response header: %s",
                self.resp_header.command,
            )
            self.transport.close()
        self.connection_event.set_result(self)

    def eof_received(self):
        self.data_received_event.set()
        if not self.connection_event.done():
            logger.error(
                "Unexpected EOF received from remote server %s:%s",
                *self.transport.get_extra_info("peername"),
            )
            self.connection_event.set_exception(EOFError)

    def connection_lost(self, exc: Exception | None):
        self.data_received_event.set()
        if exc is None:
            return
        if isinstance(exc, ConnectionError):
            logger.error(
                "Connection to %s:%s lost due to connection error: %s",
                self.host,
                self.port,
                exc,
            )
        else:
            logger.exception(
                "Connection to %s:%s lost due to unknown error",
                self.host,
                self.port,
            )
        if not self.connection_event.done():
            self.connection_event.set_exception(exc)

    async def wait_connection(self):
        return await self.connection_event

    def send_data(self, data: bytes):
        self.bytes_sent += (data_length := len(data))
        if self.header is None:
            self.send_queue.append(data)
            logger.debug("%d bytes queued for sending", data_length)
            return
        for i in range(0, data_length, _MAX_PACKET_SIZE):
            self.transport.write(self.encoder.encode(data[i : i + _MAX_PACKET_SIZE]))
        logger.debug("Sending %d bytes to remote server", data_length)

    async def recv_data(self):
        if not self.connection_event.done():
            raise RuntimeError("Connection not established yet")

        while not self.transport.is_closing():
            await self.data_received_event.wait()

            data = b""
            should_continue = True

            while self.reader.remaining and should_continue:
                before_offset = self.reader.offset
                before_masker_cursor = self.resp_encoder.masker.buffer_cursor
                received = b""
                try:
                    data += (received := self.resp_encoder.decode_once(self.reader))
                except ReadOutOfBoundError:
                    self.reader.offset = before_offset
                    self.resp_encoder.masker.buffer_cursor = before_masker_cursor
                    logger.debug("Not enough data to decode, waiting for more data")
                    break
                # once the decoded data is empty, indicates EOF
                if not received:
                    should_continue = False

            yield data

            if not should_continue:
                logger.debug("EOF received from remote server")
                break
            self.data_received_event.clear()
        return
