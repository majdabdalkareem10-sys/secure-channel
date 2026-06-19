# Goal: Convert protected messages to bytes that can be sent over TCP.

"""
SecureChannel packet format.

This module joins the header, ciphertext, and authentication tag
into one byte string. It can also separate them after receiving.
"""

from src.protocol.channel import ProtectedMessage


LENGTH_FIELD_SIZE = 4
TAG_SIZE = 16
PACKET_PREFIX_SIZE = 8


def serialize_packet(message: ProtectedMessage) -> bytes:
    """
    Convert a protected message into one byte string.

    The packet contains:
    header length, ciphertext length, header, ciphertext, and tag.
    """
    if len(message.header) == 0:
        raise ValueError("Packet header must not be empty")

    if len(message.tag) != TAG_SIZE:
        raise ValueError("Authentication tag must be 16 bytes")

    header_length = len(message.header).to_bytes(
        LENGTH_FIELD_SIZE,
        "big",
    )

    ciphertext_length = len(message.ciphertext).to_bytes(
        LENGTH_FIELD_SIZE,
        "big",
    )

    return (
        header_length
        + ciphertext_length
        + message.header
        + message.ciphertext
        + message.tag
    )


def parse_packet(packet: bytes) -> ProtectedMessage:
    """
    Separate packet bytes into header, ciphertext, and tag.
    """
    minimum_size = PACKET_PREFIX_SIZE + TAG_SIZE

    if len(packet) < minimum_size:
        raise ValueError("Packet is too short")

    header_length = int.from_bytes(
        packet[0:4],
        "big",
    )

    ciphertext_length = int.from_bytes(
        packet[4:8],
        "big",
    )

    expected_size = (
        PACKET_PREFIX_SIZE
        + header_length
        + ciphertext_length
        + TAG_SIZE
    )

    if len(packet) != expected_size:
        raise ValueError("Packet length is not correct")

    header_start = PACKET_PREFIX_SIZE
    header_end = header_start + header_length

    ciphertext_end = header_end + ciphertext_length

    header = packet[header_start:header_end]
    ciphertext = packet[header_end:ciphertext_end]
    tag = packet[ciphertext_end:]

    if len(header) == 0:
        raise ValueError("Packet header must not be empty")

    return ProtectedMessage(
        header=header,
        ciphertext=ciphertext,
        tag=tag,
    )