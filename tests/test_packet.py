# Goal: Test converting protected messages to and from packet bytes.

"""
Tests for the SecureChannel packet format.

These tests check serialization, parsing, and invalid packet lengths.
"""

import pytest

from src.protocol.channel import ProtectedMessage
from src.protocol.packet import (
    PACKET_PREFIX_SIZE,
    TAG_SIZE,
    parse_packet,
    serialize_packet,
)


HEADER = b"example-header"
CIPHERTEXT = b"encrypted-message"
TAG = bytes.fromhex("11" * 16)


def create_test_message() -> ProtectedMessage:
    """
    Create a simple protected message for packet tests.
    """
    return ProtectedMessage(
        header=HEADER,
        ciphertext=CIPHERTEXT,
        tag=TAG,
    )


def test_serialize_and_parse_packet():
    """
    Parsing a serialized packet must return the original values.
    """
    original = create_test_message()

    packet = serialize_packet(original)
    parsed = parse_packet(packet)

    assert parsed.header == original.header
    assert parsed.ciphertext == original.ciphertext
    assert parsed.tag == original.tag


def test_packet_contains_length_prefix():
    """
    The packet must start with two 4-byte length fields.
    """
    message = create_test_message()
    packet = serialize_packet(message)

    header_length = int.from_bytes(packet[0:4], "big")
    ciphertext_length = int.from_bytes(packet[4:8], "big")

    assert header_length == len(HEADER)
    assert ciphertext_length == len(CIPHERTEXT)


def test_packet_total_size():
    """
    Check the complete packet size.
    """
    message = create_test_message()
    packet = serialize_packet(message)

    expected_size = (
        PACKET_PREFIX_SIZE
        + len(HEADER)
        + len(CIPHERTEXT)
        + TAG_SIZE
    )

    assert len(packet) == expected_size


def test_short_packet_is_rejected():
    """
    A packet without enough fields must be rejected.
    """
    with pytest.raises(ValueError):
        parse_packet(b"short")


def test_incorrect_packet_length_is_rejected():
    """
    Removing bytes from a valid packet must cause an error.
    """
    message = create_test_message()
    packet = serialize_packet(message)

    shortened_packet = packet[:-1]

    with pytest.raises(ValueError):
        parse_packet(shortened_packet)


def test_wrong_tag_size_is_rejected():
    """
    Protected messages must contain a 16-byte tag.
    """
    message = ProtectedMessage(
        header=HEADER,
        ciphertext=CIPHERTEXT,
        tag=b"wrong",
    )

    with pytest.raises(ValueError):
        serialize_packet(message)


def test_empty_ciphertext_is_allowed():
    """
    Control messages may contain an empty encrypted plaintext.
    """
    message = ProtectedMessage(
        header=HEADER,
        ciphertext=b"",
        tag=TAG,
    )

    packet = serialize_packet(message)
    parsed = parse_packet(packet)

    assert parsed.ciphertext == b""