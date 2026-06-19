# Goal: Test building and reading SecureChannel message headers.

"""
Tests for the SecureChannel message header.

These tests check that header fields are stored correctly
and that invalid or modified headers are rejected.
"""

import pytest

from src.protocol.message import (
    FIXED_HEADER_SIZE,
    MESSAGE_TYPE_CHAT,
    PROTOCOL_VERSION,
    build_header,
    parse_header,
)


def test_build_and_parse_header():
    """
    Building and parsing a header must return the original values.
    """
    header_bytes = build_header(
        message_type=MESSAGE_TYPE_CHAT,
        sender_id="Majd",
        sequence_number=0,
    )

    header = parse_header(header_bytes)

    assert header.message_type == MESSAGE_TYPE_CHAT
    assert header.sender_id == "Majd"
    assert header.sequence_number == 0


def test_same_values_create_same_header():
    """
    The same fields must always create the same header bytes.
    """
    first = build_header(
        MESSAGE_TYPE_CHAT,
        "client",
        5,
    )

    second = build_header(
        MESSAGE_TYPE_CHAT,
        "client",
        5,
    )

    assert first == second


def test_sequence_number_changes_header():
    """
    Different sequence numbers must create different headers.
    """
    first = build_header(
        MESSAGE_TYPE_CHAT,
        "client",
        1,
    )

    second = build_header(
        MESSAGE_TYPE_CHAT,
        "client",
        2,
    )

    assert first != second


def test_empty_sender_id_is_rejected():
    """
    A message must contain a sender identity.
    """
    with pytest.raises(ValueError):
        build_header(
            MESSAGE_TYPE_CHAT,
            "",
            0,
        )


def test_wrong_protocol_version_is_rejected():
    """
    A header from an unsupported protocol version must be rejected.
    """
    header_bytes = bytearray(
        build_header(
            MESSAGE_TYPE_CHAT,
            "client",
            0,
        )
    )

    header_bytes[0] = PROTOCOL_VERSION + 1

    with pytest.raises(ValueError):
        parse_header(bytes(header_bytes))


def test_incorrect_header_length_is_rejected():
    """
    A shortened or incomplete header must be rejected.
    """
    header_bytes = build_header(
        MESSAGE_TYPE_CHAT,
        "client",
        0,
    )

    shortened_header = header_bytes[:-1]

    with pytest.raises(ValueError):
        parse_header(shortened_header)


def test_header_has_fixed_part_and_sender_id():
    """
    The total size must include the fixed fields and sender bytes.
    """
    header_bytes = build_header(
        MESSAGE_TYPE_CHAT,
        "Majd",
        10,
    )

    assert len(header_bytes) == FIXED_HEADER_SIZE + len(b"Majd")