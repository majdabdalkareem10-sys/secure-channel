# Goal: Authenticate the handshake and derive session keys for both sides.

"""
SecureChannel handshake.

This module creates temporary X25519 keys, builds the handshake transcript,
authenticates it using the shared PSK, and derives session keys using HKDF.
"""

from dataclasses import dataclass

from src.crypto.hkdf import hkdf
from src.crypto.hmac import hmac_sha256, verify_hmac_sha256
from src.crypto.sha256 import sha256
from src.crypto.x25519 import (
    generate_private_key,
    public_key_from_private,
    shared_secret,
)


PROTOCOL_VERSION = b"SecureChannel-v1"

KEY_SIZE = 32
NONCE_SIZE = 12

# 32 + 32 bytes for keys, and 12 + 12 bytes for nonce bases.
SESSION_MATERIAL_SIZE = 88


@dataclass
class SessionKeys:
    """
    Store the keys and nonce bases used by one side of the connection.
    """

    send_key: bytes
    receive_key: bytes
    send_nonce_base: bytes
    receive_nonce_base: bytes


def create_ephemeral_keypair() -> tuple[bytes, bytes]:
    """
    Generate a temporary X25519 private key and public key.

    A new key pair should be used for every connection.
    """
    private_key = generate_private_key()
    public_key = public_key_from_private(private_key)

    return private_key, public_key


def _encode_field(value: bytes) -> bytes:
    """
    Add a 2-byte length before a handshake field.

    This helps both sides separate the fields correctly.
    """
    if len(value) > 65535:
        raise ValueError("Handshake field is too long")

    field_length = len(value).to_bytes(2, "big")
    return field_length + value


def build_transcript(
    client_id: bytes,
    server_id: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
) -> bytes:
    """
    Build the handshake transcript in one fixed order.

    Both client and server must create exactly the same transcript.
    """
    if len(client_public_key) != KEY_SIZE:
        raise ValueError("Client public key must be 32 bytes")

    if len(server_public_key) != KEY_SIZE:
        raise ValueError("Server public key must be 32 bytes")

    return (
        _encode_field(PROTOCOL_VERSION)
        + _encode_field(client_id)
        + _encode_field(server_id)
        + _encode_field(client_public_key)
        + _encode_field(server_public_key)
    )


def create_handshake_tag(psk: bytes, transcript: bytes) -> bytes:
    """
    Create an HMAC tag for the complete handshake transcript.

    The tag proves that the sender knows the shared PSK.
    """
    if len(psk) == 0:
        raise ValueError("PSK must not be empty")

    return hmac_sha256(psk, transcript)


def verify_handshake_tag(
    psk: bytes,
    transcript: bytes,
    received_tag: bytes,
) -> bool:
    """
    Verify the HMAC tag received from the other side.
    """
    if len(psk) == 0:
        return False

    return verify_hmac_sha256(psk, transcript, received_tag)


def derive_session_keys(
    private_key: bytes,
    peer_public_key: bytes,
    psk: bytes,
    transcript: bytes,
    is_client: bool,
) -> SessionKeys:
    """
    Derive separate keys and nonce bases for both directions.

    The client send key matches the server receive key.
    The server send key matches the client receive key.
    """
    if len(private_key) != KEY_SIZE:
        raise ValueError("Private key must be 32 bytes")

    if len(peer_public_key) != KEY_SIZE:
        raise ValueError("Peer public key must be 32 bytes")

    if len(psk) == 0:
        raise ValueError("PSK must not be empty")

    # Both sides calculate the same X25519 shared secret.
    secret = shared_secret(private_key, peer_public_key)

    # An all-zero secret means the peer public key is not valid.
    if secret == b"\x00" * KEY_SIZE:
        raise ValueError("Invalid X25519 shared secret")

    # Connect the session keys to this exact handshake.
    transcript_hash = sha256(transcript)

    info = b"SecureChannel session keys|" + transcript_hash

    # Use the PSK as the HKDF salt.
    material = hkdf(
        input_key_material=secret,
        length=SESSION_MATERIAL_SIZE,
        salt=psk,
        info=info,
    )

    # Split the HKDF output into keys and nonce bases.
    client_to_server_key = material[0:32]
    server_to_client_key = material[32:64]

    client_nonce_base = material[64:76]
    server_nonce_base = material[76:88]

    if is_client:
        return SessionKeys(
            send_key=client_to_server_key,
            receive_key=server_to_client_key,
            send_nonce_base=client_nonce_base,
            receive_nonce_base=server_nonce_base,
        )

    return SessionKeys(
        send_key=server_to_client_key,
        receive_key=client_to_server_key,
        send_nonce_base=server_nonce_base,
        receive_nonce_base=client_nonce_base,
    )