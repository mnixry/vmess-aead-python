import asyncio
import enum
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from logging import getLogger
from typing import ClassVar

from vmess_aead.cli.client import VMessClientConfig, VMessClientProtocol
from vmess_aead.cli.utils import compare_iterable
from vmess_aead.enums import VMessBodyCommand
from vmess_aead.utils.reader import BaseReader, BytesReader

logger = getLogger(__name__)

_AddressUnion = IPv4Address | IPv6Address | str


class SocksProtocolErrorType(IntEnum):
    SUCCESS = 0x00
    """Success"""
    GENERAL_FAILURE = 0x01
    """General SOCKS server failure"""
    NOT_ALLOWED = 0x02
    """Connection not allowed by ruleset"""
    NETWORK_UNREACHABLE = 0x03
    """Network unreachable"""
    HOST_UNREACHABLE = 0x04
    """Host unreachable"""
    CONNECTION_REFUSED = 0x05
    """Connection refused"""
    TTL_EXPIRED = 0x06
    """TTL expired"""
    COMMAND_NOT_SUPPORTED = 0x07
    """Command not supported"""
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
    """Address type not supported"""


class SocksAuthMethodType(IntEnum):
    NO_AUTHENTICATION_REQUIRED = 0x00
    """No authentication required"""
    GSSAPI = 0x01
    """GSSAPI"""
    USERNAME_PASSWORD = 0x02
    """Username/password"""
    NO_ACCEPTABLE_METHODS = 0xFF
    """No acceptable methods"""


class SocksDestinationCommand(IntEnum):
    CONNECT = 0x01
    """Connect"""
    BIND = 0x02
    """Bind"""
    UDP_ASSOCIATE = 0x03
    """UDP associate"""


class SocksAddressType(IntEnum):
    IPV4 = 0x01
    """IPv4"""
    DOMAIN_NAME = 0x03
    """Domain name"""
    IPV6 = 0x04
    """IPv6"""


class SocksProtocolError(ValueError):
    def __init__(
        self,
        message: str,
        *args,
        error_type: SocksProtocolErrorType = SocksProtocolErrorType.GENERAL_FAILURE,
    ):
        self.error_type = error_type
        super().__init__(message, *args)


class SocksProtocolState(enum.IntEnum):
    HANDSHAKE = enum.auto()
    AUTHENTICATED = enum.auto()
    NEGOTIATING = enum.auto()
    CONNECTED = enum.auto()


@dataclass
class SocksDestinationRequest:
    command: SocksDestinationCommand
    reserved: int
    address_type: SocksAddressType
    address: _AddressUnion
    port: int

    @classmethod
    def from_packet(cls, reader: BaseReader):
        version = reader.read_byte()
        if version != 5:
            raise SocksProtocolError("invalid protocol version")
        command = SocksDestinationCommand(reader.read_byte())
        reserved = reader.read_byte()
        address_type = SocksAddressType(reader.read_byte())
        match address_type:
            case SocksAddressType.IPV4:
                address = IPv4Address(reader.read_uint32())
            case SocksAddressType.DOMAIN_NAME:
                address = reader.read(reader.read_byte()).decode()
            case SocksAddressType.IPV6:
                address = IPv6Address(reader.read_uint128())
            case _:
                raise SocksProtocolError("invalid address type")
        port = reader.read_uint16()
        return cls(command, reserved, address_type, address, port)


@dataclass
class SocksDestinationResponse:
    reply: SocksProtocolErrorType
    reserved: int
    address_type: SocksAddressType
    address: _AddressUnion
    port: int

    def to_packet(self):
        packet = b"\x05"
        packet += self.reply.to_bytes(1, "big")
        packet += self.reserved.to_bytes(1, "big")
        packet += self.address_type.to_bytes(1, "big")
        match self.address:
            case IPv4Address(packed=packed) | IPv6Address(packed=packed):
                packet += packed
            case _:
                packet += len(self.address).to_bytes(1, "big")
                packet += self.address.encode()
        packet += self.port.to_bytes(2, "big")
        return packet


@dataclass
class Socks5DatagramPacket:
    reserved: int
    fragment: int
    address_type: SocksAddressType
    address: str | IPv4Address | IPv6Address
    port: int
    data: bytes

    @classmethod
    def from_packet(cls, reader: BaseReader):
        version = reader.read_byte()
        if version != 5:
            raise SocksProtocolError("invalid protocol version")
        reserved = reader.read_byte()
        fragment = reader.read_byte()
        address_type = SocksAddressType(reader.read_byte())
        match address_type:
            case SocksAddressType.IPV4:
                address = IPv4Address(reader.read_uint32())
            case SocksAddressType.DOMAIN_NAME:
                address = reader.read(reader.read_byte()).decode()
            case SocksAddressType.IPV6:
                address = IPv6Address(reader.read_uint128())
            case _:
                raise SocksProtocolError("invalid address type")
        port = reader.read_uint16()
        data = reader.read_all()
        return cls(reserved, fragment, address_type, address, port, data)

    def to_packet(self):
        packet = b"\x00"
        packet += self.reserved.to_bytes(1, "big")
        packet += self.fragment.to_bytes(1, "big")
        packet += self.address_type.to_bytes(1, "big")
        match self.address:
            case IPv4Address(packed=packed) | IPv6Address(packed=packed):
                packet += packed
            case _:
                packet += len(self.address).to_bytes(1, "big")
                packet += self.address.encode()
        packet += self.port.to_bytes(2, "big")
        packet += self.data
        return packet


class Socks5Protocol(asyncio.Protocol):
    def __init__(
        self,
        config: VMessClientConfig,
        *,
        auth: tuple[str, str] | None = None,
        udp_associate: bool = False,
    ):
        self.auth = auth
        self.config = config
        self.udp_associate = udp_associate

        self.reader = BytesReader()
        self.state = SocksProtocolState.HANDSHAKE

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport
        logger.info("Socks5 connection from %s:%s", *self.peer_address)

    @property
    def peer_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("peername")

    @property
    def local_address(self) -> tuple[str, int]:
        return self.transport.get_extra_info("sockname")

    def data_received(self, data: bytes) -> None:
        self.reader.append(data)
        logger.debug("Received %d bytes from %s:%s", len(data), *self.peer_address)
        try:
            self._data_received()
        except SocksProtocolError as e:
            logger.exception("Error occurred while processing SOCKS5 request")
            self._close_with_error(e)

    def _close_with_error(self, error: SocksProtocolError | None = None):
        if error and self.dest:
            self.transport.write(
                SocksDestinationResponse(
                    error.error_type,
                    0,
                    SocksAddressType.IPV4,
                    IPv4Address(0),
                    0,
                ).to_packet()
            )
        else:
            self.transport.write(b"\x05\xff")
        self.transport.close()

    def _data_received(self):
        match self.state:
            case SocksProtocolState.HANDSHAKE:
                self._auth_connection()
            case SocksProtocolState.AUTHENTICATED:
                self._negotiate_dest()
            case SocksProtocolState.NEGOTIATING:
                pass
            case SocksProtocolState.CONNECTED:
                self.remote_protocol.send_data(self.reader.read_all())

    def _auth_connection(self):
        version = self.reader.read_byte()
        if version != 5:
            raise SocksProtocolError("invalid protocol version")
        methods = [
            SocksAuthMethodType(self.reader.read_byte())
            for _ in range(self.reader.read_byte())
        ]

        auth_response = b"\x05"
        auth_success = False
        match self.auth:
            case tuple(expected) if SocksAuthMethodType.USERNAME_PASSWORD in methods:
                auth_response += b"\x02"  # username/password authentication
                if (version := self.reader.read_byte()) != 1:
                    raise SocksProtocolError(f"invalid authentication {version=}")
                auth_response += b"\x01"  # version
                username = self.reader.read(self.reader.read_byte()).decode()
                password = self.reader.read(self.reader.read_byte()).decode()
                if compare_iterable((username, password), expected):
                    auth_response += b"\x00"  # success
                    auth_success = True
                else:
                    auth_response += b"\x01"  # failure
            case None if SocksAuthMethodType.NO_AUTHENTICATION_REQUIRED in methods:
                auth_response += b"\x00"  # no authentication
                auth_success = True
            case _:
                raise SocksProtocolError("no acceptable methods")
        self.transport.write(auth_response)
        if not auth_success:
            raise SocksProtocolError("authentication failed")
        self.state = SocksProtocolState.AUTHENTICATED

        if self.reader.remaining:
            self._negotiate_dest()

    def _negotiate_dest(self):
        self.dest = SocksDestinationRequest.from_packet(self.reader)
        self.state = SocksProtocolState.NEGOTIATING

        match self.dest.command:
            case SocksDestinationCommand.CONNECT:
                asyncio.create_task(self._connect()).add_done_callback(
                    self._connect_exception_handler
                )
            case _:
                raise SocksProtocolError(
                    "invalid command",
                    error_type=SocksProtocolErrorType.COMMAND_NOT_SUPPORTED,
                )

    async def _connect(self):
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_connection(
            lambda: VMessClientProtocol(
                self.dest.address,
                self.dest.port,
                VMessBodyCommand.TCP,
                config=self.config,
            ),
            self.config.server_host,
            self.config.server_port,
        )
        local_addr, local_port = self.local_address
        local_addr = ip_address(local_addr)
        match local_addr:
            case IPv4Address():
                address_type = SocksAddressType.IPV4
            case IPv6Address():
                address_type = SocksAddressType.IPV6
        reply = SocksDestinationResponse(
            SocksProtocolErrorType.SUCCESS,
            0,
            address_type,
            local_addr,
            local_port,
        )
        self.transport.write(reply.to_packet())

        self.state = SocksProtocolState.CONNECTED
        self.remote_protocol = protocol
        await protocol.wait_connection()

        async for data in protocol.recv_data():
            if self.transport.is_closing():
                break
            self.transport.write(data)
        self.transport.write_eof()

    def _connect_exception_handler(self, fut: asyncio.Future):
        if fut.cancelled():
            self._close_with_error(
                SocksProtocolError(
                    "connection cancelled",
                    error_type=SocksProtocolErrorType.GENERAL_FAILURE,
                )
            )
            return

        if not (exc := fut.exception()):
            return

        logger.exception("Connection error occurred", exc_info=exc)

        match exc:
            case asyncio.TimeoutError():
                error_type = SocksProtocolErrorType.NETWORK_UNREACHABLE
            case ConnectionError() | EOFError():
                error_type = SocksProtocolErrorType.CONNECTION_REFUSED
            case SocksProtocolError(error_type=error_type):
                logger.warning("socks5 protocol failure occurred: %s", exc)
            case _:
                error_type = SocksProtocolErrorType.GENERAL_FAILURE

        self._close_with_error(
            SocksProtocolError("connection error", error_type=error_type)
        )

    def eof_received(self):
        self.remote_protocol.send_data(b"")
        self.remote_protocol.transport.write_eof()
        logger.info("EOF received from socks5 client %s:%s", *self.peer_address)
        return

    def connection_lost(self, exc: Exception | None) -> None:
        self.remote_protocol.transport.close()
        if exc:
            logger.exception(
                "Connection to socks5 client %s:%s lost due to unexpected error",
                *self.peer_address,
            )
        return


class Socks5RelayProtocol(asyncio.DatagramProtocol):
    connections: ClassVar[
        dict[tuple[tuple[str, int], tuple[_AddressUnion, int]], VMessClientProtocol]
    ] = {}  # (src, dst) -> protocol, src = (ip, port), dst = (ip, port)

    def __init__(self, config: VMessClientConfig, *, connection_timeout: int = 10):
        self.config = config
        self.connection_timeout = connection_timeout

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        logger.debug("Received %d bytes UDP packet from %s:%s", len(data), *addr)

        packet = Socks5DatagramPacket.from_packet(BytesReader(data))

        if packet.fragment:
            logger.debug("Fragmented UDP packet from %s:%s dropped", *addr)
            return

        dst = (packet.address, packet.port)
        connection_tuple = (addr, dst)
        protocol = type(self).connections.get(connection_tuple)

        if not protocol or protocol.transport.is_closing():
            protocol = VMessClientProtocol(
                packet.address,
                packet.port,
                VMessBodyCommand.UDP,
                config=self.config,
            )
            type(self).connections[connection_tuple] = protocol

            asyncio.create_task(
                self._create_connection(addr, protocol)
            ).add_done_callback(lambda fut: self._connection_end_handler(protocol, fut))

        protocol.send_data(packet.data)

    async def _create_connection(
        self, sendto: tuple[str, int], protocol: VMessClientProtocol
    ):
        loop = asyncio.get_event_loop()

        await loop.create_connection(
            lambda: protocol,
            self.config.server_host,
            self.config.server_port,
        )

        await protocol.wait_connection()

        recv_data = protocol.recv_data()
        while not protocol.transport.is_closing():
            try:
                data = await asyncio.wait_for(anext(recv_data), self.connection_timeout)
            except TimeoutError:
                logger.debug(
                    "UDP connection from %s:%s closed, no recent activity", *sendto
                )
                break
            except StopAsyncIteration:
                break
            self.transport.sendto(data, sendto)

    def _connection_end_handler(
        self, protocol: VMessClientProtocol, fut: asyncio.Future
    ):
        try:
            fut.result()
            protocol.transport.write_eof()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Connection error occurred")
        self.transport.close()
        protocol.transport.close()
