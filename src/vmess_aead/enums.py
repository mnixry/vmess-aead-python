from enum import IntEnum, IntFlag


class VMessBodyOptions(IntFlag):
    CHUNK_STREAM = 0x01
    CONNECTION_REUSE = 0x02
    """DEPRECATED, not implemented"""
    CHUNK_MASKING = 0x04
    GLOBAL_PADDING = 0x08
    AUTHENTICATED_LENGTH = 0x10


class VMessBodySecurity(IntEnum):
    AES_128_CFB = 0x01
    AES_128_GCM = 0x03
    CHACHA20_POLY1305 = 0x04
    NONE = 0x05

    SM4_GCM = 0x0A
    """extensive implementation, not applicable to V2Ray Core"""


class VMessBodyCommand(IntEnum):
    TCP = 0x01
    UDP = 0x02
    MUX = 0x03


class VMessBodyAddressType(IntEnum):
    IPV4 = 0x01
    DOMAIN = 0x02
    IPV6 = 0x03


class VMessResponseBodyOptions(IntFlag):
    TCP_REUSE = 0x01
    """DEPRECATED, not implemented"""
