# Goal: Build and read the plaintext header used with secure messages.

"""
SecureChannel message header.

The header is not encrypted, but it will be authenticated later as AAD.
It contains the protocol version, message type, sender ID, and sequence number.
"""

from dataclasses import dataclass


PROTOCOL_VERSION = 1

MESSAGE_TYPE_CHAT = 1
MESSAGE_TYPE_CLOSE = 2

MAX_SEQUENCE_NUMBER = (1 << 64) - 1

# Version: 1 byte
# Message type: 1 byte
# Sender ID length: 2 bytes
# Sequence number: 8 bytes
FIXED_HEADER_SIZE = 12


@dataclass
class MessageHeader:
    """
    Store the values found inside a message header.
    """

    message_type: int
    sender_id: str
    sequence_number: int


def build_header(
    message_type: int,
    sender_id: str,
    sequence_number: int,
) -> bytes:
    """
    Convert the message header fields into bytes.

    The returned bytes will later be used as AEAD associated data.
    """
    if not 0 <= message_type <= 255:
        raise ValueError("Message type must fit in one byte")

    if not 0 <= sequence_number <= MAX_SEQUENCE_NUMBER:
        raise ValueError("Sequence number must fit in 8 bytes")

    sender_bytes = sender_id.encode("utf-8")

    if len(sender_bytes) == 0:
        raise ValueError("Sender ID must not be empty")

    if len(sender_bytes) > 65535:
        raise ValueError("Sender ID is too long")

    version_bytes = PROTOCOL_VERSION.to_bytes(1, "big")
    type_bytes = message_type.to_bytes(1, "big")
    sender_length_bytes = len(sender_bytes).to_bytes(2, "big")
    sequence_bytes = sequence_number.to_bytes(8, "big")

    return (
        version_bytes
        + type_bytes
        + sender_length_bytes
        + sequence_bytes
        + sender_bytes
    )


def parse_header(header_bytes: bytes) -> MessageHeader:
    """
    Read header bytes and return the original header fields.
    """
    if len(header_bytes) < FIXED_HEADER_SIZE:
        raise ValueError("Header is too short")

    version = header_bytes[0]

    if version != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version")

    message_type = header_bytes[1]

    sender_length = int.from_bytes(
        header_bytes[2:4],
        "big",
    )

    sequence_number = int.from_bytes(
        header_bytes[4:12],
        "big",
    )

    expected_length = FIXED_HEADER_SIZE + sender_length

    if len(header_bytes) != expected_length:
        raise ValueError("Header length is not correct")

    sender_bytes = header_bytes[12:]

    try:
        sender_id = sender_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Sender ID is not valid UTF-8") from error

    if sender_id == "":
        raise ValueError("Sender ID must not be empty")

    return MessageHeader(
        message_type=message_type,
        sender_id=sender_id,
        sequence_number=sequence_number,
    )