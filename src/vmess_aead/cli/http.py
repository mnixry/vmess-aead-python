import asyncio
import enum
import logging
from base64 import b64decode
from dataclasses import dataclass
from http import HTTPMethod, HTTPStatus
from urllib.parse import ParseResult, urlparse

from multidict import CIMultiDict

from vmess_aead.cli.client import VMessClientConfig, VMessClientProtocol
from vmess_aead.enums import VMessBodyCommand
from vmess_aead.utils.reader import BaseReader, BytesReader

logger = logging.getLogger(__name__)


class HTTPProxyProtocolError(ValueError):
    def __init__(
        self, message: str, code: HTTPStatus = HTTPStatus.BAD_REQUEST, *args
    ) -> None:
        self.message = message
        self.code = code
        super().__init__(message, *args)


_CRLF = b"\r\n"
_HTTP_1_1 = "HTTP/1.1"


class H11HeaderParserState(enum.IntEnum):
    REQUEST_LINE = enum.auto()
    HEADER = enum.auto()
    END = enum.auto()


@dataclass
class H11RequestHeader:
    method: str
    dest: tuple[str, int] | None
    url: ParseResult | None
    auth: tuple[str, str] | None
    keep_alive: bool
    headers: CIMultiDict[str]

    @classmethod
    def from_packet(cls, reader: BaseReader):
        request_line = reader.read_until(_CRLF)

        match request_line.decode(errors="ignore").split(" "):
            case [method, uri, protocol]:
                pass
            case _:
                raise HTTPProxyProtocolError("Invalid request line")

        if protocol.strip() != _HTTP_1_1:
            raise HTTPProxyProtocolError(
                "Unsupported protocol version",
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
            )

        # URI parsing, see https://tools.ietf.org/html/rfc7230#section-5.3
        if method == HTTPMethod.CONNECT:
            # The URI must be a valid authority
            netloc, url = uri, None
        elif (url := urlparse(uri)).scheme:
            # The URI must be an absolute URI
            netloc = url.netloc
        else:
            raise HTTPProxyProtocolError("Invalid URI format")

        match netloc.split(":"):
            case [host] if url and (port := {"http": 80, "https": 443}.get(url.scheme)):
                dest = (host, port)
            case [host, port]:
                dest = (host, int(port))
            case _:
                dest = None

        headers = CIMultiDict[str]()
        while True:
            line = reader.read_until(_CRLF).decode().strip()
            if not line:
                break
            match line.split(": "):
                case [k, v]:
                    headers[k] = v
                case _:
                    raise HTTPProxyProtocolError("Invalid header")

        match headers.pop("Proxy-Authorization", None):
            case str(auth):
                type_, _, data = auth.partition(" ")
                if type_ != "Basic":
                    raise HTTPProxyProtocolError(
                        "Unsupported authentication",
                        HTTPStatus.PROXY_AUTHENTICATION_REQUIRED,
                    )
                username, _, password = b64decode(data).decode().partition(":")
                auth = (username, password)
            case _:
                auth = None

        keep_alive = headers.pop("Proxy-Connection", "").lower() == "keep-alive"

        return cls(method, dest, url, auth, keep_alive, headers)

    def to_packet(self):
        if not self.url:
            raise ValueError("URL is required")
        absolute_path = self.url._replace(scheme="", netloc="", params="").geturl()
        header = f"{self.method} {absolute_path} {_HTTP_1_1}\r\n"
        for k, v in self.headers.items():
            header += f"{k}: {v}\r\n"
        header += "\r\n"
        return header.encode()


@dataclass
class H11ResponseHeader:
    status_code: int
    status_message: str
    content_length: int
    headers: CIMultiDict[str]

    @classmethod
    def from_packet(cls, reader: BaseReader):
        status_line = reader.read_until(_CRLF)

        match status_line.decode(errors="ignore").split(" "):
            case [protocol, status_code, status_message]:
                status_code = int(status_code)
            case _:
                raise HTTPProxyProtocolError("Invalid status line")

        if protocol.strip() != _HTTP_1_1:
            raise HTTPProxyProtocolError(
                "Unsupported protocol version",
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
            )

        headers = CIMultiDict[str]()
        while True:
            line = reader.read_until(_CRLF).decode().strip()
            if not line:
                break
            match line.split(": "):
                case [k, v]:
                    headers[k] = v.strip()
                case _:
                    raise HTTPProxyProtocolError("Invalid header")

        content_length = int(headers.get("Content-Length", -1))

        return cls(int(status_code), status_message, content_length, headers)

    def to_packet(self):
        header = f"{_HTTP_1_1} {self.status_code} {self.status_message}\r\n"
        for k, v in self.headers.items():
            header += f"{k}: {v}\r\n"
        header += "\r\n"
        return header.encode()


class HTTPProxyProtocolState(enum.IntEnum):
    HANDSHAKE = 0
    CONNECT = 1
    PLAIN_HTTP = 2


class HTTPProxyProtocol(asyncio.Protocol):
    request: H11RequestHeader | None = None
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
        self.state = HTTPProxyProtocolState.HANDSHAKE

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
            logger.debug(
                "HTTP Proxy error: %d %s from %s:%s",
                e.code,
                e.message,
                *self.peer_address,
            )
            self._close_with_error(e)

    def _data_received(self) -> None:
        match self.state:
            case HTTPProxyProtocolState.HANDSHAKE:
                self._handshake()
            case HTTPProxyProtocolState.CONNECT:
                assert self.remote_protocol
                self.remote_protocol.send_data(self.reader.read_all())
            case HTTPProxyProtocolState.PLAIN_HTTP:
                assert self.remote_protocol
                self.remote_protocol.send_data(self.reader.read_all())

    def _handshake(self) -> None:
        request = H11RequestHeader.from_packet(self.reader)
        if self.auth and self.auth != request.auth:
            raise HTTPProxyProtocolError(
                "Proxy authentication failed", HTTPStatus.PROXY_AUTHENTICATION_REQUIRED
            )
        self.request = request

        if self.request.method == HTTPMethod.CONNECT:
            task = asyncio.create_task(self._handle_connect())
        else:
            task = asyncio.create_task(self._handle_plain_http())
        task.add_done_callback(self._connection_exception_handler)

    async def _handle_connect(self):
        assert self.request
        assert self.request.dest

        host, port = self.request.dest

        loop = asyncio.get_event_loop()
        _, protocol = await loop.create_connection(
            lambda: VMessClientProtocol(
                host, port, VMessBodyCommand.TCP, config=self.config
            ),
            self.config.server_host,
            self.config.server_port,
        )
        self.remote_protocol = protocol
        self.transport.write(f"{_HTTP_1_1} 200 Connection established\r\n\r\n".encode())
        protocol.send_data(self.reader.read_all())
        await protocol.wait_connection()

        self.state = HTTPProxyProtocolState.CONNECT

        async for data in protocol.recv_data():
            self.transport.write(data)

    async def _handle_plain_http(self):
        assert self.request
        if self.request.dest is None:
            raise HTTPProxyProtocolError("Invalid request URL")
        forwarded_request = H11RequestHeader(
            method=self.request.method,
            dest=None,
            url=self.request.url,
            auth=self.request.auth,
            keep_alive=False,
            headers=self.request.headers.copy(),
        )
        forwarded_request.headers["Host"] = "{}:{}".format(*self.request.dest)

        host, port = self.request.dest

        loop = asyncio.get_event_loop()
        _, protocol = await loop.create_connection(
            lambda: VMessClientProtocol(
                host, port, VMessBodyCommand.TCP, config=self.config
            ),
            self.config.server_host,
            self.config.server_port,
        )
        self.remote_protocol = protocol
        protocol.send_data(forwarded_request.to_packet())
        protocol.send_data(self.reader.read_all())
        await protocol.wait_connection()

        data_recv = protocol.recv_data()

        response = await anext(data_recv)
        response_reader = BytesReader(response)
        response_header = H11ResponseHeader.from_packet(response_reader)

        self.state = HTTPProxyProtocolState.PLAIN_HTTP

        if remote_keep_alive := response_header.content_length >= 0:
            response_header.headers["Proxy-Connection"] = "keep-alive"
            response_header.headers["Connection"] = "keep-alive"
            response_header.headers["Keep-Alive"] = "timeout=5, max=1000"

        self.transport.write(response_header.to_packet())
        if response_reader.remaining:
            self.transport.write(response_reader.read_all())

        async for data in data_recv:
            self.transport.write(data)

        protocol.transport.write_eof()
        if remote_keep_alive and self.request.keep_alive:
            self.state = HTTPProxyProtocolState.HANDSHAKE
            self.reader.read_all()
        else:
            self.transport.close()

    def _connection_exception_handler(self, fut: asyncio.Future):
        if fut.cancelled():
            self._close_with_error(
                HTTPProxyProtocolError(
                    "Connection cancelled", HTTPStatus.REQUEST_TIMEOUT
                )
            )
            return

        if not (exc := fut.exception()):
            return

        logger.exception("Connection error occurred", exc_info=exc)

        match exc:
            case asyncio.TimeoutError():
                new_exc = HTTPProxyProtocolError(
                    "Connection timeout", HTTPStatus.GATEWAY_TIMEOUT
                )
            case ConnectionError() | EOFError():
                new_exc = HTTPProxyProtocolError(
                    "Connection error", HTTPStatus.BAD_GATEWAY
                ).with_traceback(exc.__traceback__)
            case HTTPProxyProtocolError():
                new_exc = exc
            case _:
                new_exc = HTTPProxyProtocolError(
                    "Unknown error", HTTPStatus.INTERNAL_SERVER_ERROR
                ).with_traceback(exc.__traceback__)

        self._close_with_error(new_exc)

    def _close_with_error(self, error: HTTPProxyProtocolError):
        if self.state is HTTPProxyProtocolState.HANDSHAKE:
            message = (
                f"{_HTTP_1_1} {error.code} {error.message}\r\n"
                "Connection: close\r\n"
                "Proxy-Connection: close\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.transport.write(message.encode())
        self.transport.close()
