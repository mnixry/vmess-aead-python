import gevent.monkey

gevent.monkey.patch_all()

# ruff: noqa:E402

import hashlib
import logging
import selectors
import socket
import time
import uuid
from functools import partial

import gevent
import gevent.event
import gevent.server
from rich.logging import RichHandler
from vmess_aead import VMessAEADRequestPacketHeader, VMessAEADResponsePacketHeader
from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import VMessBodyCommand, VMessResponseBodyOptions
from vmess_aead.utils.reader import ReadOutOfBoundError, SocketReader

logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])

logger = logging.getLogger(__name__)


class SelectorServer:
    def __init__(
        self,
        host: str,
        port: int,
        user_id: uuid.UUID,
        *,
        backlog: int = 100,
        buffer_size: int = 4096,
    ):
        self.sel = selectors.DefaultSelector()
        self.user_id = user_id
        self.buffer_size = buffer_size

        server = socket.socket()
        server.bind((host, port))
        server.listen(backlog)
        server.setblocking(False)
        self.sel.register(server, selectors.EVENT_READ, self.on_connection)

    def on_connection(self, sock: socket.socket, mask: int):
        connection, address = sock.accept()
        logger.info("new connection from address=%s", address)

        reader = SocketReader(connection)
        now_time = int(time.time())
        try:
            header = VMessAEADRequestPacketHeader.from_packet(
                reader, self.user_id, timestamp=now_time
            )
        except Exception:
            logger.exception("failed to read header")
            return
        logger.debug("header received %r", header)
        connection.setblocking(False)

        resp_key = hashlib.sha256(header.payload.body_key).digest()[0:16]
        resp_iv = hashlib.sha256(header.payload.body_iv).digest()[0:16]
        resp_header = VMessAEADResponsePacketHeader(
            response_header=header.payload.response_header,
            options=VMessResponseBodyOptions(0),
            command=None,
        )

        remote_address = (str(header.payload.address), header.payload.port)

        remote_connection = socket.socket(
            socket.AF_INET,
            {
                VMessBodyCommand.TCP: socket.SOCK_STREAM,
                VMessBodyCommand.UDP: socket.SOCK_DGRAM,
            }[header.payload.command],
        )
        remote_connection.connect(remote_address)
        remote_connection.setblocking(False)

        if header.payload.command is VMessBodyCommand.UDP:
            remote_send = lambda data: remote_connection.sendto(data, remote_address)
            remote_recv = lambda: remote_connection.recvfrom(self.buffer_size)[0]
        elif header.payload.command is VMessBodyCommand.TCP:
            remote_send = lambda data: remote_connection.sendall(data)
            remote_recv = lambda: remote_connection.recv(self.buffer_size)
        else:
            raise ValueError(f"unknown command {header.payload.command}")

        connection_encoder = VMessBodyEncoder(
            header.payload.body_key,
            header.payload.body_iv,
            header.payload.options,
            header.payload.security,
            header.payload.command,
        )
        remote_encoder = VMessBodyEncoder(
            resp_key,
            resp_iv,
            header.payload.options,
            header.payload.security,
            header.payload.command,
            authenticated_length_iv=header.payload.body_iv,
            authenticated_length_key=header.payload.body_key,
        )
        transferred_data = 0

        def cleanup():
            self.sel.unregister(remote_connection)
            remote_connection.close()
            self.sel.unregister(connection)
            connection.close()
            logger.info("connection closed, transferred %d bytes", transferred_data)

        def remote_connection_callback(sock: socket.socket, mask: int):
            data = b""

            while True:
                data += (received := remote_recv())
                if (len(received) < self.buffer_size) or (len(data) >= 0x8000):
                    break

            if not data:
                logger.debug("remote connection closed")
                cleanup()

            nonlocal transferred_data
            transferred_data += len(data)

            logger.debug("recv from remote %d bytes", len(data))
            connection.sendall(remote_encoder.encode(data))
            return

        def local_connection_callback(sock: socket.socket, mask: int):
            logger.debug("recv from local")
            try:
                remote_send(connection_encoder.decode_once(reader))
            except ReadOutOfBoundError:
                logger.debug("no more data from local")
                cleanup()
            except Exception:
                logger.exception("failed to send to client")
                cleanup()

        self.sel.register(
            remote_connection,
            selectors.EVENT_READ,
            remote_connection_callback,
        )
        self.sel.register(
            connection,
            selectors.EVENT_READ,
            local_connection_callback,
        )

        connection.sendall(resp_header.to_packet(resp_key, resp_iv))

        try:
            local_connection_callback(connection, selectors.EVENT_READ)
        except BlockingIOError:
            pass


class GreenletServer:
    def __init__(
        self,
        host: str,
        port: int,
        user_id: uuid.UUID,
        *,
        backlog: int = 100,
        buffer_size: int = 4096,
    ):
        self.user_id = user_id
        self.buffer_size = buffer_size

        self.buffer_factor = 1
        self.max_buffer_size = 0x8000

        def _handler_wrapper(sock: socket.socket, address):
            try:
                return self.greenlet_handler(sock, address)
            except Exception:
                logger.exception("handler failed")

        self.server = gevent.server.StreamServer(
            (host, port), self.greenlet_handler, backlog=backlog
        )

    def __enter__(self):
        self.server.__enter__()
        return self

    def __exit__(self, *args):
        self.server.__exit__(*args)

    def serve_forever(self):
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("server stopped")

    def _send_tcp(self, sock: socket.socket, data: bytes):
        return sock.sendall(data)

    def _send_udp(self, sock: socket.socket, address, data: bytes):
        return sock.sendto(data, address)

    @property
    def _tcp_recv_buffer_size(self):
        return min(self.buffer_size * self.buffer_factor, self.max_buffer_size)

    def _recv_tcp(self, sock: socket.socket):
        data = sock.recv(expected_length := self._tcp_recv_buffer_size)
        if len(data) >= expected_length and expected_length < self.max_buffer_size:
            self.buffer_factor += 1
        return data

    def _recv_udp(self, sock: socket.socket, buffer_size: int):
        data, _ = sock.recvfrom(buffer_size)
        return data

    def greenlet_handler(self, sock: socket.socket, address):
        logger.info("new connection from address=%s", address)
        reader = SocketReader(sock)
        try:
            header = VMessAEADRequestPacketHeader.from_packet(
                reader, self.user_id, timestamp=int(time.time())
            )
        except Exception:
            logger.exception("failed to read header")
            return
        logger.debug("header received %r", header)

        resp_key = hashlib.sha256(header.payload.body_key).digest()[0:16]
        resp_iv = hashlib.sha256(header.payload.body_iv).digest()[0:16]
        resp_header = VMessAEADResponsePacketHeader(
            response_header=header.payload.response_header,
            options=VMessResponseBodyOptions(0),
            command=None,
        )

        remote_address = (str(header.payload.address), header.payload.port)
        remote_connection = socket.socket(
            socket.AF_INET,
            {
                VMessBodyCommand.TCP: socket.SOCK_STREAM,
                VMessBodyCommand.UDP: socket.SOCK_DGRAM,
            }[header.payload.command],
        )
        remote_connection.connect(remote_address)

        if header.payload.command is VMessBodyCommand.UDP:
            remote_send = partial(self._send_udp, remote_connection, remote_address)
            remote_recv = partial(self._recv_udp, remote_connection, self.buffer_size)
        elif header.payload.command is VMessBodyCommand.TCP:
            remote_send = partial(self._send_tcp, remote_connection)
            remote_recv = partial(self._recv_tcp, remote_connection)
        else:
            raise ValueError(f"unknown command {header.payload.command}")

        connection_encoder = VMessBodyEncoder(
            header.payload.body_key,
            header.payload.body_iv,
            header.payload.options,
            header.payload.security,
            header.payload.command,
        )

        remote_encoder = VMessBodyEncoder(
            resp_key,
            resp_iv,
            header.payload.options,
            header.payload.security,
            header.payload.command,
            authenticated_length_iv=header.payload.body_iv,
            authenticated_length_key=header.payload.body_key,
        )

        close_event = gevent.event.Event()

        def remote_connection_greenlet():
            transferred_data = 0
            while not close_event.is_set():
                try:
                    data: bytes = gevent.with_timeout(1, remote_recv)
                except gevent.Timeout:
                    continue
                if not data:
                    logger.debug("remote connection closed")
                    close_event.set()
                    break
                transferred_data += (remote_length := len(data))
                logger.debug("recv from remote %d bytes", remote_length)
                sock.sendall(remote_encoder.encode(data))
            logger.info("remote closed, transferred %d bytes", transferred_data)

        def local_connection_greenlet():
            transferred_data = 0
            while not close_event.is_set():
                try:
                    decoded = connection_encoder.decode_once(reader)
                    transferred_data += (local_length := len(decoded))
                    remote_send(decoded)
                except ReadOutOfBoundError:
                    logger.debug("no more data from local")
                    close_event.set()
                    break
                except Exception:
                    logger.exception("failed to send to client")
                    close_event.set()
                    break
                logger.debug("recv from local %d bytes", local_length)
            logger.info("local closed, transferred %d bytes", transferred_data)

        remote_greenlet = gevent.spawn(remote_connection_greenlet)
        local_greenlet = gevent.spawn(local_connection_greenlet)

        sock.sendall(resp_header.to_packet(resp_key, resp_iv))

        gevent.joinall([remote_greenlet, local_greenlet], raise_error=True)


if __name__ == "__main__":
    # server = SelectorServer(
    #     "0.0.0.0", 10086, uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    # )
    # logger.info("server started %r", server)
    # while True:
    #     events = server.sel.select()
    #     for key, mask in events:
    #         if key.data is None:
    #             logger.warning("unknown callback for %s", key.fileobj)
    #             continue
    #         callback = key.data

    #         begin = time.time()
    #         logger.debug("callback %s started, mask=%s", callback, mask)
    #         try:
    #             callback(key.fileobj, mask)
    #         except Exception:
    #             logger.exception("callback failed")
    #         elapsed = (time.time() - begin) * 1000
    #         logger.debug(
    #             "callback %s finished, mask=%s, time=%s", callback, mask, elapsed
    #         )

    with GreenletServer(
        "0.0.0.0", 10086, uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    ) as server:
        logger.info("server started %r", server)
        server.serve_forever()
