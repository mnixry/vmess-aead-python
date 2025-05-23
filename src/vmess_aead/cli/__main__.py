import asyncio
import contextlib
import logging
import uuid
from typing import Annotated

from vmess_aead.cli.client import VMessClientConfig
from vmess_aead.cli.http import HTTPProxyProtocol
from vmess_aead.cli.server import VMessServerProtocol
from vmess_aead.cli.socks5 import Socks5Protocol
from vmess_aead.enums import VMessBodySecurity

try:
    import click
    import typer
    from rich.logging import RichHandler
except ImportError as e:
    raise ImportError(
        "Please install the extra dependencies for the CLI: pip install vmess-aead[cli]"
    ) from e

app = typer.Typer()


UUIDType = Annotated[
    uuid.UUID,
    typer.Option(
        envvar="USER_ID",
        help="User ID to identify the client or server.",
    ),
]
_DEFAULT_USER_ID = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")

ListenPortType = Annotated[
    int,
    typer.Option(
        envvar="LISTEN_PORT",
        help="Port to listen or connect.",
        click_type=click.IntRange(0x0000, 0xFFFF, min_open=True),
    ),
]

ListenAddrType = Annotated[
    str,
    typer.Option(
        envvar="LISTEN_ADDR",
        help="Address to listen.",
    ),
]

EnableUDPType = Annotated[
    bool,
    typer.Option(
        envvar="ENABLE_UDP",
        help="Enable UDP relay.",
    ),
]


@app.command()
def server(
    user_id: UUIDType = _DEFAULT_USER_ID,
    listen_port: ListenPortType = 10086,
    listen_addr: ListenAddrType = "0.0.0.0",
    enable_udp: EnableUDPType = True,
):
    async def server_main():
        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: VMessServerProtocol(user_id, enable_udp=enable_udp),
            host=listen_addr,
            port=listen_port,
        )
        logging.info("Listening on %s:%d", listen_addr, listen_port)

        async with server:
            with contextlib.suppress(KeyboardInterrupt):
                await server.serve_forever()
        return

    asyncio.run(server_main())


ServerPortType = Annotated[
    int,
    typer.Option(
        envvar="SERVER_PORT",
        help="Port to connect.",
        click_type=click.IntRange(0x0000, 0xFFFF, min_open=True),
    ),
]

ServerAddrType = Annotated[
    str,
    typer.Option(
        envvar="SERVER_ADDR",
        help="Address to connect.",
    ),
]

LocalProtocolType = Annotated[
    str,
    typer.Option(
        envvar="LOCAL_PROTOCOL",
        help="Local proxy protocol to use.",
        click_type=click.Choice(["SOCKS5", "HTTP"], case_sensitive=False),
    ),
]

ConnectionTimeoutType = Annotated[
    float,
    typer.Option(
        envvar="CONNECTION_TIMEOUT",
        help="Connection timeout to the server, in seconds.",
        click_type=click.FloatRange(0, min_open=True),
    ),
]

VMessProtocolSecurityType = Annotated[
    str,
    typer.Option(
        envvar="SECURITY",
        help="Security protocol to use.",
        click_type=click.Choice(
            [security.name for security in VMessBodySecurity],
            case_sensitive=False,
        ),
    ),
]


@app.command()
def client(
    server_addr: ServerAddrType = "127.0.0.1",
    server_port: ServerPortType = 10086,
    user_id: UUIDType = _DEFAULT_USER_ID,
    listen_port: ListenPortType = 1080,
    listen_addr: ListenAddrType = "127.0.0.1",
    enable_udp: EnableUDPType = False,
    local_protocol: LocalProtocolType = "SOCKS5",
    connection_timeout: ConnectionTimeoutType = 10,
    security: VMessProtocolSecurityType = "AES_128_GCM",
):
    if local_protocol != "SOCKS5" and enable_udp:
        typer.echo(
            f"[bold red]UDP relay is not supported for {local_protocol=}[/bold red]"
        )

    async def client_main():
        config = VMessClientConfig(
            server_host=server_addr,
            server_port=server_port,
            user_id=user_id,
            security=VMessBodySecurity[security],
            timeout=connection_timeout,
        )
        loop = asyncio.get_running_loop()
        client_protocol = (
            Socks5Protocol if local_protocol == "SOCKS5" else HTTPProxyProtocol
        )
        server = await loop.create_server(
            lambda: client_protocol(config),
            host=listen_addr,
            port=listen_port,
        )
        logging.info("Listening on %s:%d", listen_addr, listen_port)
        async with server:
            with contextlib.suppress(KeyboardInterrupt):
                await server.serve_forever()
        return

    asyncio.run(client_main())


LogLevelType = Annotated[
    str,
    typer.Option(
        envvar="LOG_LEVEL",
        click_type=click.Choice(
            [*logging.getLevelNamesMapping().keys()],
            case_sensitive=False,
        ),
        help="Logging level, set lower than INFO may reduce performance.",
    ),
]


@app.callback()
def main(log_level: LogLevelType = "DEBUG"):
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )


if __name__ == "__main__":
    app()
