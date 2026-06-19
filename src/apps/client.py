# Goal: Run the SecureChannel client and exchange encrypted messages.

"""
SecureChannel client application.

The client connects to the server, performs the authenticated handshake,
and then exchanges encrypted text messages with the server.
"""

import socket

from src.protocol.message import (
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_CLOSE,
)
from src.protocol.socket_handshake import client_handshake
from src.protocol.transport import (
    receive_protected_message,
    send_protected_message,
)


HOST = "127.0.0.1"
PORT = 5000

CLIENT_ID = "client"
EXPECTED_SERVER_ID = "server"


def read_psk() -> bytes:
    """
Read the shared PSK from the user.
    """
    psk_text = input("Enter shared PSK: ")
    if psk_text == "":
        raise ValueError("PSK must not be empty")

    return psk_text.encode("utf-8")


def send_text_message(
    connection: socket.socket,
    channel,
    text: str,
    message_type: int,
) -> None:
    """
    Encrypt and send one text message to the server.
    """
    protected_message = channel.encrypt_message(
        plaintext=text.encode("utf-8"),
        message_type=message_type,
    )

    send_protected_message(
        connection,
        protected_message,
    )


def receive_text_message(
    connection: socket.socket,
    channel,
) -> tuple[int, str]:
    """
    Receive, verify, decrypt, and decode one server message.
    """
    protected_message = receive_protected_message(
        connection
    )

    header, plaintext = channel.decrypt_message(
        protected_message
    )

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Message is not valid UTF-8") from error

    return header.message_type, text


def run_client() -> None:
    """
    Connect to the server and start secure messaging.
    """
    psk = read_psk()

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as client_socket:
        client_socket.connect((HOST, PORT))

        print(f"Connected to server at {HOST}:{PORT}")

        channel = client_handshake(
            client_socket,
            client_id=CLIENT_ID,
            expected_server_id=EXPECTED_SERVER_ID,
            psk=psk,
        )

        print("Secure handshake completed.")
        print("Type /quit to close the connection.")

        while True:
            message = input("Client: ")

            if message.strip() == "/quit":
                send_text_message(
                    client_socket,
                    channel,
                    "",
                    MESSAGE_TYPE_CLOSE,
                )
                break

            send_text_message(
                client_socket,
                channel,
                message,
                MESSAGE_TYPE_CHAT,
            )

            message_type, reply = receive_text_message(
                client_socket,
                channel,
            )

            if message_type == MESSAGE_TYPE_CLOSE:
                print("Server closed the connection.")
                break

            if message_type != MESSAGE_TYPE_CHAT:
                raise ValueError("Unknown message type")

            print(f"Server: {reply}")


if __name__ == "__main__":
    try:
        run_client()
    except (OSError, ValueError, ConnectionError) as error:
        print(f"Client error: {error}")