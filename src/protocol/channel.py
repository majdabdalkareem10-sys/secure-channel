# Goal: Encrypt session messages and reject modified or replayed messages.

"""
SecureChannel message protection.

This module creates a unique nonce for each message and uses
ChaCha20-Poly1305 to encrypt and authenticate session messages.
"""

from dataclasses import dataclass

from src.crypto.aead import (
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)
from src.protocol.message import (
    MAX_SEQUENCE_NUMBER,
    MESSAGE_TYPE_CHAT,
    MessageHeader,
    build_header,
    parse_header,
)


KEY_SIZE = 32
NONCE_SIZE = 12


@dataclass
class ProtectedMessage:
    """
    Store one encrypted message with its header and authentication tag.
    """

    header: bytes
    ciphertext: bytes
    tag: bytes


def build_nonce(nonce_base: bytes, sequence_number: int) -> bytes:
    """
    Create a 12-byte nonce for one message.

    The sequence number is XORed with the session nonce base.
    Different sequence numbers create different nonces.
    """
    if len(nonce_base) != NONCE_SIZE:
        raise ValueError("Nonce base must be 12 bytes")

    if not 0 <= sequence_number <= MAX_SEQUENCE_NUMBER:
        raise ValueError("Sequence number must fit in 8 bytes")

    sequence_bytes = sequence_number.to_bytes(
        NONCE_SIZE,
        "big",
    )

    return bytes(
        base_byte ^ sequence_byte
        for base_byte, sequence_byte in zip(
            nonce_base,
            sequence_bytes,
        )
    )


class SecureChannel:
    """
    Store the session keys and sequence numbers for one connection side.
    """

    def __init__(
        self,
        send_key: bytes,
        receive_key: bytes,
        send_nonce_base: bytes,
        receive_nonce_base: bytes,
        sender_id: str,
        expected_peer_id: str,
    ):
        """
        Create a secure message channel using the session values.
        """
        if len(send_key) != KEY_SIZE:
            raise ValueError("Send key must be 32 bytes")

        if len(receive_key) != KEY_SIZE:
            raise ValueError("Receive key must be 32 bytes")

        if len(send_nonce_base) != NONCE_SIZE:
            raise ValueError("Send nonce base must be 12 bytes")

        if len(receive_nonce_base) != NONCE_SIZE:
            raise ValueError("Receive nonce base must be 12 bytes")

        if sender_id == "":
            raise ValueError("Sender ID must not be empty")

        if expected_peer_id == "":
            raise ValueError("Expected peer ID must not be empty")

        self.send_key = send_key
        self.receive_key = receive_key

        self.send_nonce_base = send_nonce_base
        self.receive_nonce_base = receive_nonce_base

        self.sender_id = sender_id
        self.expected_peer_id = expected_peer_id

        self.send_sequence = 0
        self.receive_sequence = 0

    def encrypt_message(
        self,
        plaintext: bytes,
        message_type: int = MESSAGE_TYPE_CHAT,
    ) -> ProtectedMessage:
        """
        Encrypt one outgoing message.

        The header is authenticated as AAD but is not encrypted.
        """
        if self.send_sequence > MAX_SEQUENCE_NUMBER:
            raise ValueError("Send sequence number overflow")

        header = build_header(
            message_type=message_type,
            sender_id=self.sender_id,
            sequence_number=self.send_sequence,
        )

        nonce = build_nonce(
            self.send_nonce_base,
            self.send_sequence,
        )

        ciphertext, tag = chacha20_poly1305_encrypt(
            key=self.send_key,
            nonce=nonce,
            plaintext=plaintext,
            aad=header,
        )

        self.send_sequence += 1

        return ProtectedMessage(
            header=header,
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt_message(
        self,
        protected_message: ProtectedMessage,
    ) -> tuple[MessageHeader, bytes]:
        """
        Verify and decrypt one incoming message.

        The message is rejected when the sender, sequence number,
        ciphertext, header, or authentication tag is not correct.
        """
        header = parse_header(protected_message.header)

        if header.sender_id != self.expected_peer_id:
            raise ValueError("Unexpected sender ID")

        if header.sequence_number != self.receive_sequence:
            raise ValueError("Unexpected sequence number")

        nonce = build_nonce(
            self.receive_nonce_base,
            header.sequence_number,
        )

        plaintext = chacha20_poly1305_decrypt(
            key=self.receive_key,
            nonce=nonce,
            ciphertext=protected_message.ciphertext,
            tag=protected_message.tag,
            aad=protected_message.header,
        )

        # Increase only after successful authentication and decryption.
        self.receive_sequence += 1

        return header, plaintext