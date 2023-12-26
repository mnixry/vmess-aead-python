import hashlib
import logging
import selectors
import socket
import time
import uuid

from vmess_aead import VMessAEADRequestPacketHeader, VMessAEADResponsePacketHeader
from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.enums import VMessResponseBodyOptions
from vmess_aead.utils.reader import ReadOutOfBoundError, SocketReader

logging.basicConfig(level=logging.INFO)

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
        remote_connection = socket.socket()
        remote_connection.connect(remote_address)
        remote_connection.setblocking(False)

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
                data += (received := remote_connection.recv(self.buffer_size))
                if (len(received) < self.buffer_size) or (len(data) >= 2**14):
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
                remote_connection.sendall(connection_encoder.decode_once(reader))
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
            connection.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            pass
        else:
            local_connection_callback(connection, selectors.EVENT_READ)


if __name__ == "__main__":
    server = SelectorServer(
        "0.0.0.0", 10086, uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    )
    logger.info("server started %r", server)
    while True:
        events = server.sel.select()
        for key, mask in events:
            if key.data is None:
                logger.warning("unknown callback for %s", key.fileobj)
                continue
            callback = key.data

            begin = time.time()
            logger.debug("callback %s started, mask=%s", callback, mask)
            try:
                callback(key.fileobj, mask)
            except Exception:
                logger.exception("callback failed")
            elapsed = (time.time() - begin) * 1000
            logger.debug(
                "callback %s finished, mask=%s, time=%s", callback, mask, elapsed
            )
