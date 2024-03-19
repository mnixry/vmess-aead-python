import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from rich.logging import RichHandler
from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import VMessBodyCommand, VMessResponseBodyOptions
from vmess_aead.headers.request import VMessAEADRequestPacketHeader
from vmess_aead.headers.response import VMessAEADResponsePacketHeader
from vmess_aead.utils.reader import BytesReader

logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)


_NetworkTransport = asyncio.DatagramTransport | asyncio.WriteTransport
_MAX_PACKET_SIZE = 0xFFFF - 0xFF  # 64KB minus additional overhead


@dataclass(frozen=True)
class TransferSpeed:
    elapsed: float
    transferred: int

    unit_format: Literal["bits", "bytes"] = "bytes"
    """display unit format, either bits or bytes per second"""
    si: bool = False
    """use SI unit (1 KB = 1000 bytes) or IEC unit (1 KiB = 1024 bytes)"""

    @staticmethod
    def _digit_scale(value: float | int, base: int) -> str:
        scales = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"]
        scale = 0
        while value >= base:
            value /= base
            scale += 1
        return f"{value:.2f} {scales[scale]}"

    @property
    def human_readable_size(self) -> str:
        text = self._digit_scale(self.transferred, 1024 if not self.si else 1000)
        text += "B" if not self.si else "iB"
        return text

    @property
    def human_readable_rate(self) -> str:
        rate = self.transferred / self.elapsed
        text = self._digit_scale(
            rate * 8 if self.unit_format == "bits" else rate,
            1024 if not self.si else 1000,
        )
        text += (
            "bps" if self.unit_format == "bits" else "B/s" if not self.si else "iB/s"
        )
        return text

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.__str__()}>"

    def __str__(self) -> str:
        text = f"in {timedelta(seconds=self.elapsed)}"
        text += f", {self.human_readable_size} transferred"
        text += f", at {self.human_readable_rate} rate"
        return text


class VMessServerProtocol(asyncio.Protocol):
    header: VMessAEADRequestPacketHeader | None = None
    remote_transport: _NetworkTransport | None = None

    def __init__(self, user_id: uuid.UUID) -> None:
        self.reader = BytesReader(b"")
        self.user_id = user_id

        self.data_transferred = 0
        self.start_time = time.time()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        logger.info(
            "Connection made from %s:%s",
            *transport.get_extra_info("peername"),
        )
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        self.data_transferred += (data_length := len(data))
        logger.debug("%d bytes received", data_length)

        self.reader.append(data)

        if self.header is None:
            self._initial_connection()

        if self.remote_transport:
            self._feed_body()

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

        self.encoder = VMessBodyEncoder(
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
            remote_task = loop.create_task(
                loop.create_connection(
                    lambda: VMessServerRemoteConnectionProtocol(
                        remote_encoder, self.transport
                    ),
                    host=str(self.header.payload.address),
                    port=self.header.payload.port,
                )
            )
        elif self.header.payload.command is VMessBodyCommand.UDP:
            remote_task = loop.create_task(
                loop.create_datagram_endpoint(
                    lambda: VMessServerRemoteDatagramProtocol(
                        remote_encoder, self.transport
                    ),
                    remote_addr=(
                        str(self.header.payload.address),
                        self.header.payload.port,
                    ),
                )
            )
        else:
            raise ValueError("Invalid command")

        remote_task.add_done_callback(self._remote_connection_made)
        self.transport.write(resp_header.to_packet(resp_key, resp_iv))

    def _remote_connection_made(
        self, ret: asyncio.Task[tuple[_NetworkTransport, Any]]
    ) -> None:
        if ret.cancelled():
            self.transport.close()
            return
        if exc := ret.exception():
            logger.exception("Error occurred during remote connection", exc_info=exc)
            self.transport.close()
            return
        self.remote_transport, _ = ret.result()

        if isinstance(self.remote_transport, asyncio.DatagramTransport):
            self.remote_send = self.remote_transport.sendto
        else:
            self.remote_send = self.remote_transport.write

        self._feed_body()

    def _feed_body(self):
        while self.reader.remaining:
            data = self.encoder.decode_once(self.reader)
            if not data:
                self.transport.write_eof()
                if isinstance(self.remote_transport, asyncio.WriteTransport):
                    self.remote_transport.write_eof()
                break
            self.remote_send(data)

    def eof_received(self):
        time_taken = time.time() - self.start_time
        logger.info(
            "EOF received from local connection %s:%s, %s",
            *self.transport.get_extra_info("peername"),
            TransferSpeed(time_taken, self.data_transferred),
        )
        if isinstance(self.remote_transport, asyncio.WriteTransport):
            self.remote_transport.write_eof()
        elif isinstance(self.remote_transport, asyncio.DatagramTransport):
            self.remote_transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            return
        logger.exception(
            "Connection abnormal closed from local connection %s:%s",
            *self.transport.get_extra_info("peername"),
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
        self.start_time = time.time()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        self.data_transferred += (data_length := len(data))
        logger.debug("%d bytes received from remote connection", data_length)

        for i in range(0, len(data), _MAX_PACKET_SIZE):
            self.local_transport.write(
                self.encoder.encode(data[i : i + _MAX_PACKET_SIZE])
            )

    def eof_received(self):
        time_taken = time.time() - self.start_time
        logger.info(
            "EOF received from remote connection %s:%s, %s",
            *self.transport.get_extra_info("peername"),
            TransferSpeed(time_taken, self.data_transferred),
        )
        self.local_transport.write_eof()

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            return
        logger.exception(
            "Connection abnormal closed from remote connection %s:%s",
            *self.transport.get_extra_info("peername"),
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
