import asyncio
import enum
import logging
from base64 import b64decode
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

from vmess_aead.cli.client import VMessClientConfig, VMessClientProtocol
from vmess_aead.enums import VMessBodyCommand
from vmess_aead.utils.reader import BaseReader, BytesReader

logger = logging.getLogger(__name__)


class HTTPProxyProtocolError(ValueError):
    def __init__(self, message: str, code: int = 400, *args) -> None:
        self.message = message
        self.code = code
        super().__init__(message, *args)


class HTTPProxyState(enum.IntEnum):
    HANDSHAKE = enum.auto()
    CONNECT = enum.auto()
    FORWARD = enum.auto()


_CRLF = b"\r\n"
_HTTP_1_1 = "HTTP/1.1"


@dataclass
class HTTPRequest:
    method: str
    dest: tuple[str, int] | None
    url: ParseResult | None
    auth: tuple[str, str] | None
    keep_alive: bool
    headers: dict[str, str]

    @classmethod
    def from_packet(cls, reader: BaseReader):
        request_line = reader.read_until(_CRLF)
        parts = request_line.split(b" ")
        if len(parts) != 3:
            raise HTTPProxyProtocolError("Invalid request line", 400)
        method, url, protocol = map(bytes.decode, parts)

        if method == "CONNECT":
            netloc, url = url, None
        else:
            url = urlparse(url)
            netloc = url.netloc
        match netloc.split(":"):
            case [host] if url and (port := {"http": 80, "https": 443}.get(url.scheme)):
                dest = (host, port)
            case [host, port]:
                dest = (host, int(port))
            case _:
                dest = None

        if protocol != _HTTP_1_1:
            raise HTTPProxyProtocolError("Protocol not supported", 505)

        headers: dict[str, str] = {}
        while True:
            line = reader.read_until(_CRLF).decode()
            if not line:
                break
            match line.split(": "):
                case [k, v]:
                    headers[k] = v
                case _:
                    raise HTTPProxyProtocolError("Invalid header", 400)
        auth = headers.get("Proxy-Authorization")

        match headers.get("Proxy-Authorization"):
            case str(auth):
                type_, _, data = auth.partition(" ")
                if type_ != "Basic":
                    raise HTTPProxyProtocolError("Unsupported authentication", 407)
                username, _, password = b64decode(data).decode().partition(":")
                auth = (username, password)
            case _:
                auth = None

        keep_alive = headers.get("Proxy-Connection", "close").lower() == "keep-alive"

        return cls(method, dest, url, auth, keep_alive, headers)


class HTTPProxyProtocol(asyncio.Protocol):
    request: HTTPRequest | None = None
    remote_protocol: VMessClientProtocol | None = None

    def __init__(
        self,
        config: VMessClientConfig,
        *,
        auth: tuple[str, str] | None = None,
    ) -> None:
        self.config = config
        self.auth = auth

        self.reader = BytesReader(b"")
        self.state = HTTPProxyState.HANDSHAKE

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport
        logger.info("HTTP Proxy connection from %s:%s", *self.peer_address)

    @property
    def peer_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("peername")

    @property
    def local_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("sockname")

    def data_received(self, data: bytes) -> None:
        self.reader.append(data)
        try:
            self._data_received()
        except HTTPProxyProtocolError as e:
            logger.warning(
                "HTTP Proxy error: %d %s from %s:%s",
                e.code,
                e.message,
                *self.peer_address,
            )
            message = (
                f"{_HTTP_1_1} {e.code} {e.message}\r\n"
                "Connection: close\r\n"
                "Proxy-Connection: close\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.transport.write(message.encode())
            self.transport.close()

    def _data_received(self) -> None:
        match self.state:
            case HTTPProxyState.HANDSHAKE:
                self._handshake()
        return

    def _handshake(self) -> None:
        request = HTTPRequest.from_packet(self.reader)
        if self.auth and self.auth != request.auth:
            raise HTTPProxyProtocolError("Proxy authentication failed", 407)
        self.request = request

        if request.url is None:
            self.state = HTTPProxyState.CONNECT
            self.request = request
            self.transport.write(
                f"{_HTTP_1_1} 200 Connection established\r\n\r\n".encode()
            )

    def _plain_http_proxy(self) -> None:
        assert self.request
        if self.request.dest is None:
            raise HTTPProxyProtocolError("Invalid request URL", 400)
        forwarded_request = HTTPRequest(
            method=self.request.method,
            dest=None,
            url=self.request.url,
            auth=self.request.auth,
            keep_alive=False,
            headers=self.request.headers.copy(),
        )
        forwarded_request.headers["Host"] = "{}:{}".format(*self.request.dest)

    async def _establish_connection(self) -> None:
        assert self.request and self.request.dest
        host, port = self.request.dest

        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_connection(
            lambda: VMessClientProtocol(
                host, port, VMessBodyCommand.TCP, config=self.config
            ),
            self.config.server_host,
            self.config.server_port,
        )
        await protocol.wait_connection()

        self.remote_protocol = protocol
