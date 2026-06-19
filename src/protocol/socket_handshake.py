# Goal: Perform the authenticated handshake through a TCP socket.

"""
SecureChannel socket handshake.

This module exchanges temporary public keys and identities,
authenticates both sides with the PSK, and creates a secure channel.
"""

import socket

from src.protocol.channel import SecureChannel
from src.protocol.handshake import (
    PROTOCOL_VERSION,
    build_transcript,
    create_ephemeral_keypair,
    create_handshake_tag,
    derive_session_keys,
    verify_handshake_tag,
)
from src.protocol.transport import receive_exact


LENGTH_SIZE = 4
MAX_HANDSHAKE_FIELD_SIZE = 4096

CLIENT_FINISHED_LABEL = b"client-finished|"
SERVER_FINISHED_LABEL = b"server-finished|"


def _send_field(sock: socket.socket, data: bytes) -> None:
    """
    Send one handshake field with a 4-byte length before it.
    """
    if len(data) == 0:
        raise ValueError("Handshake field must not be empty")

    if len(data) > MAX_HANDSHAKE_FIELD_SIZE:
        raise ValueError("Handshake field is too large")

    field_length = len(data).to_bytes(
        LENGTH_SIZE,
        "big",
    )

    sock.sendall(field_length + data)


def _receive_field(sock: socket.socket) -> bytes:
    """
    Receive one complete length-prefixed handshake field.
    """
    length_bytes = receive_exact(
        sock,
        LENGTH_SIZE,
    )

    field_length = int.from_bytes(
        length_bytes,
        "big",
    )

    if field_length <= 0:
        raise ValueError("Handshake field length must be positive")

    if field_length > MAX_HANDSHAKE_FIELD_SIZE:
        raise ValueError("Handshake field is too large")

    return receive_exact(
        sock,
        field_length,
    )


def _encode_identity(identity: str) -> bytes:
    """
    Convert a text identity to UTF-8 bytes.
    """
    if identity == "":
        raise ValueError("Identity must not be empty")

    identity_bytes = identity.encode("utf-8")

    if len(identity_bytes) > MAX_HANDSHAKE_FIELD_SIZE:
        raise ValueError("Identity is too long")

    return identity_bytes


def client_handshake(
    sock: socket.socket,
    client_id: str,
    expected_server_id: str,
    psk: bytes,
) -> SecureChannel:
    """
    Run the client side of the authenticated handshake.

    The client sends its public key first, verifies the server,
    and then returns a ready SecureChannel object.
    """
    if len(psk) == 0:
        raise ValueError("PSK must not be empty")

    client_id_bytes = _encode_identity(client_id)
    expected_server_id_bytes = _encode_identity(
        expected_server_id
    )

    client_private, client_public = create_ephemeral_keypair()

    # Send the client hello fields.
    _send_field(sock, PROTOCOL_VERSION)
    _send_field(sock, client_id_bytes)
    _send_field(sock, client_public)

    # Receive the server hello fields.
    server_version = _receive_field(sock)
    server_id_bytes = _receive_field(sock)
    server_public = _receive_field(sock)

    if server_version != PROTOCOL_VERSION:
        raise ValueError("Unsupported server protocol version")

    if server_id_bytes != expected_server_id_bytes:
        raise ValueError("Unexpected server identity")

    transcript = build_transcript(
        client_id=client_id_bytes,
        server_id=server_id_bytes,
        client_public_key=client_public,
        server_public_key=server_public,
    )

    # Prove that the client knows the PSK.
    client_tag = create_handshake_tag(
        psk,
        CLIENT_FINISHED_LABEL + transcript,
    )

    _send_field(sock, client_tag)

    # Verify that the server also knows the PSK.
    server_tag = _receive_field(sock)

    if not verify_handshake_tag(
        psk,
        SERVER_FINISHED_LABEL + transcript,
        server_tag,
    ):
        raise ValueError("Server authentication failed")

    session_keys = derive_session_keys(
        private_key=client_private,
        peer_public_key=server_public,
        psk=psk,
        transcript=transcript,
        is_client=True,
    )

    return SecureChannel(
        send_key=session_keys.send_key,
        receive_key=session_keys.receive_key,
        send_nonce_base=session_keys.send_nonce_base,
        receive_nonce_base=session_keys.receive_nonce_base,
        sender_id=client_id,
        expected_peer_id=expected_server_id,
    )


def server_handshake(
    sock: socket.socket,
    server_id: str,
    expected_client_id: str,
    psk: bytes,
) -> SecureChannel:
    """
    Run the server side of the authenticated handshake.

    The server verifies the client and returns a ready
    SecureChannel object.
    """
    if len(psk) == 0:
        raise ValueError("PSK must not be empty")

    server_id_bytes = _encode_identity(server_id)
    expected_client_id_bytes = _encode_identity(
        expected_client_id
    )

    # Receive the client hello fields.
    client_version = _receive_field(sock)
    client_id_bytes = _receive_field(sock)
    client_public = _receive_field(sock)

    if client_version != PROTOCOL_VERSION:
        raise ValueError("Unsupported client protocol version")

    if client_id_bytes != expected_client_id_bytes:
        raise ValueError("Unexpected client identity")

    server_private, server_public = create_ephemeral_keypair()

    # Send the server hello fields.
    _send_field(sock, PROTOCOL_VERSION)
    _send_field(sock, server_id_bytes)
    _send_field(sock, server_public)

    transcript = build_transcript(
        client_id=client_id_bytes,
        server_id=server_id_bytes,
        client_public_key=client_public,
        server_public_key=server_public,
    )

    # Verify that the client knows the PSK.
    client_tag = _receive_field(sock)

    if not verify_handshake_tag(
        psk,
        CLIENT_FINISHED_LABEL + transcript,
        client_tag,
    ):
        raise ValueError("Client authentication failed")

    # Prove that the server also knows the PSK.
    server_tag = create_handshake_tag(
        psk,
        SERVER_FINISHED_LABEL + transcript,
    )

    _send_field(sock, server_tag)

    session_keys = derive_session_keys(
        private_key=server_private,
        peer_public_key=client_public,
        psk=psk,
        transcript=transcript,
        is_client=False,
    )

    return SecureChannel(
        send_key=session_keys.send_key,
        receive_key=session_keys.receive_key,
        send_nonce_base=session_keys.send_nonce_base,
        receive_nonce_base=session_keys.receive_nonce_base,
        sender_id=server_id,
        expected_peer_id=expected_client_id,
    )