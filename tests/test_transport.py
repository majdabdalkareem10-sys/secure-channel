# Goal: Test sending complete protected messages through TCP sockets.

"""
Tests for SecureChannel TCP transport.

These tests use a local socket pair to check packet sending,
receiving, and connection errors.
"""

import socket

import pytest

from src.protocol.channel import ProtectedMessage
from src.protocol.transport import (
    receive_exact,
    receive_protected_message,
    send_protected_message,
)


HEADER = b"test-header"
CIPHERTEXT = b"encrypted-data"
TAG = bytes.fromhex("33" * 16)


def create_test_message() -> ProtectedMessage:
    """
    Create a protected message for transport tests.
    """
    return ProtectedMessage(
        header=HEADER,
        ciphertext=CIPHERTEXT,
        tag=TAG,
    )


def test_send_and_receive_protected_message():
    """
    A protected message must arrive with the same values.
    """
    first_socket, second_socket = socket.socketpair()

    try:
        original = create_test_message()

        send_protected_message(
            first_socket,
            original,
        )

        received = receive_protected_message(
            second_socket,
        )

        assert received.header == original.header
        assert received.ciphertext == original.ciphertext
        assert received.tag == original.tag
    finally:
        first_socket.close()
        second_socket.close()


def test_receive_exact_reads_multiple_parts():
    """
    receive_exact must join data received in separate parts.
    """
    first_socket, second_socket = socket.socketpair()

    try:
        first_socket.sendall(b"hello")
        first_socket.sendall(b"-world")

        received = receive_exact(
            second_socket,
            11,
        )

        assert received == b"hello-world"
    finally:
        first_socket.close()
        second_socket.close()


def test_receive_exact_rejects_closed_connection():
    """
    Closing the connection early must cause an error.
    """
    first_socket, second_socket = socket.socketpair()

    try:
        first_socket.sendall(b"abc")
        first_socket.close()

        with pytest.raises(ConnectionError):
            receive_exact(
                second_socket,
                10,
            )
    finally:
        second_socket.close()


def test_zero_packet_length_is_rejected():
    """
    A packet length of zero is not valid.
    """
    first_socket, second_socket = socket.socketpair()

    try:
        first_socket.sendall(
            (0).to_bytes(4, "big")
        )

        with pytest.raises(ValueError):
            receive_protected_message(
                second_socket,
            )
    finally:
        first_socket.close()
        second_socket.close()


def test_packet_larger_than_limit_is_rejected():
    """
    A packet above the maximum allowed size must be rejected.
    """
    first_socket, second_socket = socket.socketpair()

    try:
        too_large = (1024 * 1024) + 1

        first_socket.sendall(
            too_large.to_bytes(4, "big")
        )

        with pytest.raises(ValueError):
            receive_protected_message(
                second_socket,
            )
    finally:
        first_socket.close()
        second_socket.close()