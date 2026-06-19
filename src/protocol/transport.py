# Goal: Send and receive complete SecureChannel packets over TCP.

"""
SecureChannel TCP transport.

This module sends packet bytes with a length prefix and makes sure
the receiver reads the complete packet even if TCP splits the data.
"""

import socket

from src.protocol.channel import ProtectedMessage
from src.protocol.packet import parse_packet, serialize_packet


LENGTH_PREFIX_SIZE = 4
MAX_PACKET_SIZE = 1024 * 1024


def receive_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly the requested number of bytes.

    TCP may return fewer bytes than requested, so this function
    keeps receiving until all bytes arrive.
    """
    if size < 0:
        raise ValueError("Receive size must not be negative")

    received = bytearray()

    while len(received) < size:
        chunk = sock.recv(size - len(received))

        if chunk == b"":
            raise ConnectionError("Connection closed before all data arrived")

        received.extend(chunk)

    return bytes(received)


def send_protected_message(
    sock: socket.socket,
    message: ProtectedMessage,
) -> None:
    """
    Serialize and send one protected message over TCP.

    A 4-byte packet length is sent before the packet itself.
    """
    packet = serialize_packet(message)

    if len(packet) > MAX_PACKET_SIZE:
        raise ValueError("Packet is too large")

    packet_length = len(packet).to_bytes(
        LENGTH_PREFIX_SIZE,
        "big",
    )

    sock.sendall(packet_length + packet)


def receive_protected_message(
    sock: socket.socket,
) -> ProtectedMessage:
    """
    Receive one complete protected message from TCP.
    """
    length_bytes = receive_exact(
        sock,
        LENGTH_PREFIX_SIZE,
    )

    packet_length = int.from_bytes(
        length_bytes,
        "big",
    )

    if packet_length <= 0:
        raise ValueError("Packet length must be positive")

    if packet_length > MAX_PACKET_SIZE:
        raise ValueError("Packet is too large")

    packet = receive_exact(
        sock,
        packet_length,
    )

    return parse_packet(packet)