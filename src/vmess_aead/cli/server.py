import asyncio
import hashlib
import logging
import time
import uuid
from functools import cached_property
from typing import cast

from vmess_aead.cli.utils import TransferSpeed
from vmess_aead.encoding import VMessBodyDecoder, VMessBodyEncoder
from vmess_aead.enums import VMessBodyCommand, VMessResponseBodyOptions
from vmess_aead.headers.request import VMessAEADRequestPacketHeader
from vmess_aead.headers.response import VMessAEADResponsePacketHeader
from vmess_aead.utils import create_ref_task
from vmess_aead.utils.reader import BytesReader

logger = logging.getLogger(__name__)


_MAX_PACKET_SIZE = 0xFFFF - 0xFF  # 64KB minus additional overhead


class VMessServerProtocol(asyncio.Protocol):
    header: VMessAEADRequestPacketHeader | None = None
    remote_transport: asyncio.BaseTransport | None = None

    def __init__(self, user_id: uuid.UUID, *, enable_udp: bool = True) -> None:
        self.user_id = user_id
        self.enable_udp = enable_udp

        self.reader = BytesReader()
        self.data_transferred = 0
        self.start_time = time.monotonic()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport
        logger.info("Connection made from %s:%s", *self.peer_address)

    @cached_property
    def peer_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("peername")

    def data_received(self, data: bytes) -> None:
        self.data_transferred += (data_length := len(data))
        logger.debug("%d bytes received", data_length)

        self.reader.append(data)

        if self.header is None:
            self._initial_connection()

        if self.remote_transport:
            self._feed_body(data)

    def _initial_connection(self) -> None:
        try:
            self.header = VMessAEADRequestPacketHeader.from_packet(
                reader=self.reader,
                user_id=self.user_id,
                timestamp=int(time.time()),
            )
        except Exception:
            logger.exception("Invalid VMessAEAD request")
            self.transport.close()
            return

        logger.debug("VMessAEAD request header: %s", self.header)

        resp_key = hashlib.sha256(self.header.payload.body_key).digest()[0:16]
        resp_iv = hashlib.sha256(self.header.payload.body_iv).digest()[0:16]
        resp_header = VMessAEADResponsePacketHeader(
            response_header=self.header.payload.response_header,
            options=VMessResponseBodyOptions(0),
            command=None,
        )

        self.decoder = VMessBodyDecoder(
            self.header.payload.body_key,
            self.header.payload.body_iv,
            self.header.payload.options,
            self.header.payload.security,
            self.header.payload.command,
        )

        remote_encoder = VMessBodyEncoder(
            resp_key,
            resp_iv,
            self.header.payload.options,
            self.header.payload.security,
            self.header.payload.command,
            authenticated_length_iv=self.header.payload.body_iv,
            authenticated_length_key=self.header.payload.body_key,
        )

        loop = asyncio.get_running_loop()

        if self.header.payload.command is VMessBodyCommand.TCP:
            remote_task = create_ref_task(
                loop.create_connection(
                    lambda: VMessServerRemoteConnectionProtocol(
                        remote_encoder, self.transport
                    ),
                    host=str(self.header.payload.address),
                    port=self.header.payload.port,
                ),
                loop=loop,
            )
        elif self.header.payload.command is VMessBodyCommand.UDP:
            if not self.enable_udp:
                logger.debug(
                    "dropping UDP request from %s:%s due to configuration",
                    *self.peer_address,
                )
                self.transport.close()
                return
            remote_task = create_ref_task(
                loop.create_datagram_endpoint(
                    lambda: VMessServerRemoteDatagramProtocol(
                        remote_encoder, self.transport
                    ),
                    remote_addr=(
                        str(self.header.payload.address),
                        self.header.payload.port,
                    ),
                ),
                loop=loop,
            )
        else:
            raise ValueError("Invalid command")

        remote_task.add_done_callback(self._remote_connection_made)
        self.transport.write(resp_header.to_packet(resp_key, resp_iv))

    def _remote_connection_made(
        self, ret: asyncio.Task[tuple[asyncio.BaseTransport, asyncio.BaseProtocol]]
    ) -> None:
        if ret.cancelled():
            self.transport.close()
            return
        if exc := ret.exception():
            logger.exception("Error occurred during remote connection", exc_info=exc)
            self.transport.close()
            return
        self.remote_transport, _ = ret.result()

        assert self.header
        # Since bugs in Python <= 3.11, we cannot determine the type of remote_transport
        # Ref: https://github.com/python/cpython/pull/98844
        if self.header.payload.command is VMessBodyCommand.UDP:
            transport = cast(asyncio.DatagramTransport, self.remote_transport)
            self.remote_send = transport.sendto
        else:
            transport = cast(asyncio.WriteTransport, self.remote_transport)
            self.remote_send = transport.write

        self._feed_body(self.reader.read_all())

    def _feed_body(self, data: bytes):
        chunks = self.decoder.decode(data)
        for chunk in chunks:
            if not chunk:
                self.transport.write_eof()
                break
            self.remote_send(chunk)
        return

    def eof_received(self):
        time_taken = time.monotonic() - self.start_time
        logger.info(
            "EOF received from local connection %s:%s, %s",
            *self.peer_address,
            TransferSpeed(time_taken, self.data_transferred),
        )
        if self.remote_transport:
            close_func = getattr(
                self.remote_transport, "eof_received", self.remote_transport.close
            )
            close_func()

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            return
        logger.exception(
            "Connection abnormal closed from local connection %s:%s",
            *self.peer_address,
            exc_info=exc,
        )

        if self.remote_transport:
            self.remote_transport.close()


class VMessServerRemoteConnectionProtocol(asyncio.Protocol):
    def __init__(
        self,
        encoder: VMessBodyEncoder,
        local_transport: asyncio.WriteTransport,
    ) -> None:
        self.encoder = encoder
        self.local_transport = local_transport

        self.data_transferred = 0
        self.start_time = time.monotonic()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport

    @cached_property
    def peer_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("peername")

    def data_received(self, data: bytes) -> None:
        self.data_transferred += (data_length := len(data))
        logger.debug("%d bytes received from remote connection", data_length)

        for i in range(0, len(data), _MAX_PACKET_SIZE):
            self.local_transport.write(
                self.encoder.encode(data[i : i + _MAX_PACKET_SIZE])
            )

    def eof_received(self):
        time_taken = time.monotonic() - self.start_time
        logger.info(
            "EOF received from remote connection %s:%s, %s",
            *self.peer_address,
            TransferSpeed(time_taken, self.data_transferred),
        )
        self.local_transport.write_eof()

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            return
        logger.exception(
            "Connection abnormal closed from remote connection %s:%s",
            *self.peer_address,
            exc_info=exc,
        )
        self.local_transport.close()


class VMessServerRemoteDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        encoder: VMessBodyEncoder,
        local_transport: asyncio.WriteTransport,
    ) -> None:
        self.encoder = encoder
        self.local_transport = local_transport
        self.data_transferred = 0

    def datagram_received(self, data: bytes, addr) -> None:
        self.data_transferred += (data_length := len(data))
        logger.debug("%d bytes received from remote datagram %s", data_length, addr)

        self.local_transport.write(self.encoder.encode(data))

    def error_received(self, exc: Exception) -> None:
        logger.exception("Error received from remote datagram", exc_info=exc)


async def main(host: str, port: int, user_id: uuid.UUID):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: VMessServerProtocol(user_id),
        host=host,
        port=port,
    )
    logger.info("Listening on %s:%d", host, port)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(
        main("0.0.0.0", 10086, uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811"))
    )
