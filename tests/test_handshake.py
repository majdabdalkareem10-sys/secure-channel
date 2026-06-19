# Goal: Test authentication and session key derivation in the handshake.

"""
Tests for the SecureChannel handshake.

These tests check transcript creation, PSK authentication,
and session key derivation between the client and server.
"""

from src.protocol.handshake import (
    PROTOCOL_VERSION,
    build_transcript,
    create_ephemeral_keypair,
    create_handshake_tag,
    derive_session_keys,
    verify_handshake_tag,
)


CLIENT_PUBLIC_KEY = bytes.fromhex("11" * 32)
SERVER_PUBLIC_KEY = bytes.fromhex("22" * 32)

PSK = b"strong-shared-secret-between-client-and-server"


def test_build_transcript_contains_all_fields():
    """
    Check that the transcript contains all important handshake fields.
    """
    transcript = build_transcript(
        b"Majd-client",
        b"SecureChannel-server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    assert PROTOCOL_VERSION in transcript
    assert b"Majd-client" in transcript
    assert b"SecureChannel-server" in transcript
    assert CLIENT_PUBLIC_KEY in transcript
    assert SERVER_PUBLIC_KEY in transcript


def test_same_inputs_create_same_transcript():
    """
    The same handshake fields must create the same transcript.
    """
    first_transcript = build_transcript(
        b"client",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    second_transcript = build_transcript(
        b"client",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    assert first_transcript == second_transcript


def test_handshake_tag_verification_success():
    """
    A correct PSK and transcript must produce a valid tag.
    """
    transcript = build_transcript(
        b"client",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    tag = create_handshake_tag(PSK, transcript)

    assert verify_handshake_tag(PSK, transcript, tag)


def test_modified_transcript_is_rejected():
    """
    Changing one handshake field must make verification fail.
    """
    transcript = build_transcript(
        b"client",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    tag = create_handshake_tag(PSK, transcript)

    changed_transcript = build_transcript(
        b"attacker",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    assert not verify_handshake_tag(
        PSK,
        changed_transcript,
        tag,
    )


def test_wrong_psk_is_rejected():
    """
    A party without the correct PSK must fail authentication.
    """
    transcript = build_transcript(
        b"client",
        b"server",
        CLIENT_PUBLIC_KEY,
        SERVER_PUBLIC_KEY,
    )

    tag = create_handshake_tag(PSK, transcript)

    assert not verify_handshake_tag(
        b"wrong-secret",
        transcript,
        tag,
    )


def test_client_and_server_derive_matching_session_keys():
    """
    Client send values must match server receive values.
    """
    client_private, client_public = create_ephemeral_keypair()
    server_private, server_public = create_ephemeral_keypair()

    transcript = build_transcript(
        b"client",
        b"server",
        client_public,
        server_public,
    )

    client_keys = derive_session_keys(
        client_private,
        server_public,
        PSK,
        transcript,
        is_client=True,
    )

    server_keys = derive_session_keys(
        server_private,
        client_public,
        PSK,
        transcript,
        is_client=False,
    )

    assert client_keys.send_key == server_keys.receive_key
    assert client_keys.receive_key == server_keys.send_key

    assert (
        client_keys.send_nonce_base
        == server_keys.receive_nonce_base
    )

    assert (
        client_keys.receive_nonce_base
        == server_keys.send_nonce_base
    )


def test_session_key_sizes():
    """
    Check that keys and nonce bases have the required sizes.
    """
    client_private, client_public = create_ephemeral_keypair()
    server_private, server_public = create_ephemeral_keypair()

    transcript = build_transcript(
        b"client",
        b"server",
        client_public,
        server_public,
    )

    keys = derive_session_keys(
        client_private,
        server_public,
        PSK,
        transcript,
        is_client=True,
    )

    assert len(keys.send_key) == 32
    assert len(keys.receive_key) == 32

    assert len(keys.send_nonce_base) == 12
    assert len(keys.receive_nonce_base) == 12


def test_changed_transcript_creates_different_session_keys():
    """
    Changing the transcript must change the derived session keys.
    """
    client_private, client_public = create_ephemeral_keypair()
    server_private, server_public = create_ephemeral_keypair()

    first_transcript = build_transcript(
        b"client",
        b"server",
        client_public,
        server_public,
    )

    second_transcript = build_transcript(
        b"different-client",
        b"server",
        client_public,
        server_public,
    )

    first_keys = derive_session_keys(
        client_private,
        server_public,
        PSK,
        first_transcript,
        is_client=True,
    )

    second_keys = derive_session_keys(
        client_private,
        server_public,
        PSK,
        second_transcript,
        is_client=True,
    )

    assert first_keys.send_key != second_keys.send_key
    assert first_keys.send_nonce_base != second_keys.send_nonce_base