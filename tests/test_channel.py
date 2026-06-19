# Goal: Test secure encryption, nonces, and replay protection.

"""
Tests for SecureChannel message protection.

These tests check nonce creation, encryption, authentication,
sequence numbers, and replay protection.
"""

import pytest

from src.protocol.channel import (
    NONCE_SIZE,
    ProtectedMessage,
    SecureChannel,
    build_nonce,
)
from src.protocol.message import parse_header


NONCE_BASE = bytes.fromhex(
    "000102030405060708090a0b"
)

CLIENT_TO_SERVER_KEY = bytes.fromhex("10" * 32)
SERVER_TO_CLIENT_KEY = bytes.fromhex("20" * 32)

CLIENT_NONCE_BASE = bytes.fromhex(
    "000102030405060708090a0b"
)

SERVER_NONCE_BASE = bytes.fromhex(
    "101112131415161718191a1b"
)


def create_test_channels() -> tuple[SecureChannel, SecureChannel]:
    """
    Create matching client and server channels for the tests.
    """
    client = SecureChannel(
        send_key=CLIENT_TO_SERVER_KEY,
        receive_key=SERVER_TO_CLIENT_KEY,
        send_nonce_base=CLIENT_NONCE_BASE,
        receive_nonce_base=SERVER_NONCE_BASE,
        sender_id="client",
        expected_peer_id="server",
    )

    server = SecureChannel(
        send_key=SERVER_TO_CLIENT_KEY,
        receive_key=CLIENT_TO_SERVER_KEY,
        send_nonce_base=SERVER_NONCE_BASE,
        receive_nonce_base=CLIENT_NONCE_BASE,
        sender_id="server",
        expected_peer_id="client",
    )

    return client, server


def test_nonce_has_correct_size():
    """
    Every ChaCha20-Poly1305 nonce must be 12 bytes.
    """
    nonce = build_nonce(NONCE_BASE, 0)

    assert len(nonce) == NONCE_SIZE


def test_same_sequence_creates_same_nonce():
    """
    The same base and sequence must create the same nonce.
    """
    first = build_nonce(NONCE_BASE, 5)
    second = build_nonce(NONCE_BASE, 5)

    assert first == second


def test_different_sequences_create_different_nonces():
    """
    Different sequence numbers must create different nonces.
    """
    first = build_nonce(NONCE_BASE, 1)
    second = build_nonce(NONCE_BASE, 2)

    assert first != second


def test_sequence_number_changes_last_nonce_bytes():
    """
    Sequence number one must change the last nonce byte.
    """
    nonce = build_nonce(NONCE_BASE, 1)

    expected = bytes.fromhex(
        "000102030405060708090a0a"
    )

    assert nonce == expected


def test_wrong_nonce_base_size_is_rejected():
    """
    A nonce base with the wrong size must be rejected.
    """
    with pytest.raises(ValueError):
        build_nonce(b"short", 0)


def test_negative_sequence_number_is_rejected():
    """
    Sequence numbers cannot be negative.
    """
    with pytest.raises(ValueError):
        build_nonce(NONCE_BASE, -1)


def test_client_and_server_can_exchange_messages():
    """
    Client and server must decrypt each other's messages.
    """
    client, server = create_test_channels()

    protected = client.encrypt_message(
        b"Hello from client"
    )

    header, plaintext = server.decrypt_message(protected)

    assert header.sender_id == "client"
    assert header.sequence_number == 0
    assert plaintext == b"Hello from client"

    reply = server.encrypt_message(
        b"Hello from server"
    )

    reply_header, reply_plaintext = client.decrypt_message(reply)

    assert reply_header.sender_id == "server"
    assert reply_plaintext == b"Hello from server"


def test_send_sequence_number_increases():
    """
    Every outgoing message must use the next sequence number.
    """
    client, _ = create_test_channels()

    first = client.encrypt_message(b"first")
    second = client.encrypt_message(b"second")

    first_header = parse_header(first.header)
    second_header = parse_header(second.header)

    assert first_header.sequence_number == 0
    assert second_header.sequence_number == 1
    assert client.send_sequence == 2


def test_replayed_message_is_rejected():
    """
    Receiving the same message twice must be rejected.
    """
    client, server = create_test_channels()

    protected = client.encrypt_message(b"important message")

    server.decrypt_message(protected)

    with pytest.raises(ValueError):
        server.decrypt_message(protected)


def test_modified_header_is_rejected():
    """
    Changing the authenticated header must make decryption fail.
    """
    client, server = create_test_channels()

    protected = client.encrypt_message(b"secret message")

    changed_header = bytearray(protected.header)

    # Change the message type but keep the sequence number.
    changed_header[1] ^= 1

    changed_message = ProtectedMessage(
        header=bytes(changed_header),
        ciphertext=protected.ciphertext,
        tag=protected.tag,
    )

    with pytest.raises(ValueError):
        server.decrypt_message(changed_message)


def test_modified_ciphertext_is_rejected():
    """
    Changing encrypted data must make authentication fail.
    """
    client, server = create_test_channels()

    protected = client.encrypt_message(b"secret message")

    changed_ciphertext = bytearray(protected.ciphertext)
    changed_ciphertext[0] ^= 1

    changed_message = ProtectedMessage(
        header=protected.header,
        ciphertext=bytes(changed_ciphertext),
        tag=protected.tag,
    )

    with pytest.raises(ValueError):
        server.decrypt_message(changed_message)

    # The correct message should still work because the failed
    # message did not increase the receive sequence number.
    _, plaintext = server.decrypt_message(protected)

    assert plaintext == b"secret message"