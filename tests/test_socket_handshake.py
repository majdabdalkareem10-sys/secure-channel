# Goal: Test the authenticated handshake through local sockets.

"""
Tests for the SecureChannel socket handshake.

These tests check matching session keys, secure message exchange,
and rejection when the two sides use different PSKs.
"""

import socket
import threading

import pytest

from src.protocol.socket_handshake import (
    client_handshake,
    server_handshake,
)
from src.protocol.transport import (
    receive_protected_message,
    send_protected_message,
)


PSK = b"shared-secret-for-client-and-server"


def perform_successful_handshake():
    """
    Run client and server handshakes using a local socket pair.
    """
    client_socket, server_socket = socket.socketpair()

    server_result = {}

    def run_server():
        try:
            server_result["channel"] = server_handshake(
                server_socket,
                server_id="server",
                expected_client_id="client",
                psk=PSK,
            )
        except Exception as error:
            server_result["error"] = error

    server_thread = threading.Thread(
        target=run_server
    )

    server_thread.start()

    client_channel = client_handshake(
        client_socket,
        client_id="client",
        expected_server_id="server",
        psk=PSK,
    )

    server_thread.join(timeout=2)

    if server_thread.is_alive():
        raise RuntimeError("Server handshake did not finish")

    if "error" in server_result:
        raise server_result["error"]

    return (
        client_socket,
        server_socket,
        client_channel,
        server_result["channel"],
    )


def test_socket_handshake_creates_matching_channels():
    """
    Client send values must match server receive values.
    """
    (
        client_socket,
        server_socket,
        client_channel,
        server_channel,
    ) = perform_successful_handshake()

    try:
        assert (
            client_channel.send_key
            == server_channel.receive_key
        )

        assert (
            client_channel.receive_key
            == server_channel.send_key
        )

        assert (
            client_channel.send_nonce_base
            == server_channel.receive_nonce_base
        )

        assert (
            client_channel.receive_nonce_base
            == server_channel.send_nonce_base
        )
    finally:
        client_socket.close()
        server_socket.close()


def test_secure_message_after_socket_handshake():
    """
    A protected message must work after the handshake.
    """
    (
        client_socket,
        server_socket,
        client_channel,
        server_channel,
    ) = perform_successful_handshake()

    try:
        outgoing = client_channel.encrypt_message(
            b"Hello after handshake"
        )

        send_protected_message(
            client_socket,
            outgoing,
        )

        incoming = receive_protected_message(
            server_socket
        )

        header, plaintext = server_channel.decrypt_message(
            incoming
        )

        assert header.sender_id == "client"
        assert plaintext == b"Hello after handshake"
    finally:
        client_socket.close()
        server_socket.close()


def test_wrong_psk_is_rejected():
    """
    The handshake must fail when the PSKs do not match.
    """
    client_socket, server_socket = socket.socketpair()

    server_result = {}

    def run_server():
        try:
            server_handshake(
                server_socket,
                server_id="server",
                expected_client_id="client",
                psk=b"correct-server-psk",
            )
        except Exception as error:
            server_result["error"] = error
        finally:
            server_socket.close()

    server_thread = threading.Thread(
        target=run_server
    )

    server_thread.start()

    try:
        with pytest.raises(
            (ValueError, ConnectionError, BrokenPipeError)
        ):
            client_handshake(
                client_socket,
                client_id="client",
                expected_server_id="server",
                psk=b"wrong-client-psk",
            )
    finally:
        client_socket.close()

    server_thread.join(timeout=2)

    assert isinstance(
        server_result.get("error"),
        ValueError,
    )