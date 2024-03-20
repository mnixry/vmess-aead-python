import asyncio
import enum
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from logging import getLogger
from secrets import compare_digest

from vmess_aead.cli.client import VMessClientConfig, VMessClientProtocol
from vmess_aead.enums import VMessBodyCommand
from vmess_aead.utils.reader import BaseReader, BytesReader

logger = getLogger(__name__)


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
    address: str | IPv4Address | IPv6Address
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
    address: str | IPv4Address | IPv6Address
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
    ):
        self.auth = auth
        self.config = config

        self.reader = BytesReader(b"")
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
            logger.error("Error occurred while processing SOCKS5 request: %s", e)
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
            case (
                expected_username,
                expected_password,
            ) if SocksAuthMethodType.USERNAME_PASSWORD in methods:
                auth_response += b"\x02"  # username/password authentication
                if (version := self.reader.read_byte()) != 1:
                    raise SocksProtocolError(f"invalid authentication {version=}")
                auth_response += b"\x01"  # version
                username_input = self.reader.read(self.reader.read_byte()).decode()
                password_input = self.reader.read(self.reader.read_byte()).decode()
                if compare_digest(
                    username_input,
                    expected_username,
                ) and compare_digest(
                    password_input,
                    expected_password,
                ):
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
            # case SocksDestinationCommand.UDP_ASSOCIATE:
            #     self._associate_udp()
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

        logger.info(
            "Connected to remote server %s:%s",
            *transport.get_extra_info("peername"),
        )

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

    async def _associate_udp(self):
        loop = asyncio.get_event_loop()

        listen_host = self.dest.address
        listen_port = self.dest.port
        if ip_address(listen_host).packed == b"\x00\x00\x00\x00" and listen_port == 0:
            listen_host, listen_port = self.transport.get_extra_info("sockname")

        client_host, _ = self.peer_address
        _, protocol = await loop.create_connection(
            lambda: VMessClientProtocol(
                self.dest.address,
                self.dest.port,
                VMessBodyCommand.UDP,
                config=self.config,
            ),
            self.config.server_host,
            self.config.server_port,
        )
        await protocol.wait_connection()

        transport, _ = await loop.create_datagram_endpoint(
            lambda: Socks5UDPRelay(self, client_host),
            local_addr=(str(listen_host), listen_port),
        )
        local_addr, local_port = transport.get_extra_info("sockname")
        local_addr = ip_address(local_addr)
        match local_addr:
            case IPv4Address():
                address_type = SocksAddressType.IPV4
            case IPv6Address():
                address_type = SocksAddressType.IPV6
        reply = SocksDestinationResponse(
            SocksProtocolErrorType(0),
            0,
            address_type,
            local_addr,
            local_port,
        )

        self.remote_protocol = protocol
        self.transport.write(reply.to_packet())

    def eof_received(self):
        self.remote_protocol.transport.write_eof()
        return

    def connection_lost(self, exc: Exception | None) -> None:
        self.remote_protocol.transport.close()
        return super().connection_lost(exc)


class Socks5UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, parent: Socks5Protocol, acceptable_host: str):
        self.parent = parent
        self.acceptable_host = acceptable_host

        # format: {(host, port): ({index: fragment}, last_received)
        self.fragments: dict[tuple[str, int], tuple[dict[int, bytes], float]] = {}
        self.fragment_timeout = 10

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        host, port = addr
        if host != self.acceptable_host:
            logger.warning("Received UDP packet from unauthorized host: %s:%s", host)
            return
        if not self.parent.remote_protocol:
            logger.warning("Received UDP packet before remote connection established")
            return
        packet = Socks5DatagramPacket.from_packet(BytesReader(data))
        if packet.fragment != 0:
            logger.debug("Fragmented UDP packet received, dropping")
            return

    def _process_fragment(self, packet: Socks5DatagramPacket, addr: tuple[str, int]):
        # Cleanup old fragments
        for addr, (_, last_received) in [*self.fragments.items()]:
            if last_received + self.fragment_timeout < time.time():
                del self.fragments[addr]
                continue

        # highest bit of fragment is 1, so we should send the packet
        should_send = bool(packet.fragment & 0b10000000)
        packet.fragment &= 0b01111111

        if packet.fragment == 0:
            return

        existing, _ = self.fragments.pop(addr, ({}, 0))

        # If max fragment is less than current, we should drop the full fragment
        if max(existing.keys(), default=0) > packet.fragment:
            return
        existing[packet.fragment] = packet.data
        # Check continuous fragment
        if len(existing) < packet.fragment:
            return
        self.fragments[addr] = (existing, time.time())

        if not should_send:
            return
        # If we should send the packet, we should merge all
        fragments, _ = self.fragments.pop(addr)
        data = b"".join(fragments.values())


if __name__ == "__main__":
    import logging
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    async def main():
        config = VMessClientConfig(
            server_host="localhost",
            server_port=10086,
            user_id=uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811"),
        )
        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: Socks5Protocol(config),
            host="127.0.0.1",
            port=1080,
        )
        async with server:
            await server.serve_forever()

    asyncio.run(main())
