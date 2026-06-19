# Goal: Run the SecureChannel server and exchange encrypted messages.

"""
SecureChannel server application.

The server waits for one client, performs the authenticated handshake,
and then exchanges encrypted text messages with the client.
"""

import socket

from src.protocol.message import (
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_CLOSE,
)
from src.protocol.socket_handshake import server_handshake
from src.protocol.transport import (
    receive_protected_message,
    send_protected_message,
)


HOST = "127.0.0.1"
PORT = 5000

SERVER_ID = "server"
EXPECTED_CLIENT_ID = "client"


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
    Encrypt and send one text message to the client.
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
    Receive, verify, decrypt, and decode one client message.
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


def run_server() -> None:
    """
    Start the server and handle one secure client connection.
    """
    psk = read_psk()

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as server_socket:
        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server_socket.bind((HOST, PORT))
        server_socket.listen(1)

        print(f"Server listening on {HOST}:{PORT}")

        connection, address = server_socket.accept()

        with connection:
            print(f"Client connected from {address}")

            channel = server_handshake(
                connection,
                server_id=SERVER_ID,
                expected_client_id=EXPECTED_CLIENT_ID,
                psk=psk,
            )

            print("Secure handshake completed.")

            while True:
                message_type, text = receive_text_message(
                    connection,
                    channel,
                )

                if message_type == MESSAGE_TYPE_CLOSE:
                    print("Client closed the connection.")
                    break

                if message_type != MESSAGE_TYPE_CHAT:
                    raise ValueError("Unknown message type")

                print(f"Client: {text}")

                reply = input("Server: ")

                if reply.strip() == "/quit":
                    send_text_message(
                        connection,
                        channel,
                        "",
                        MESSAGE_TYPE_CLOSE,
                    )
                    break

                send_text_message(
                    connection,
                    channel,
                    reply,
                    MESSAGE_TYPE_CHAT,
                )


if __name__ == "__main__":
    try:
        run_server()
    except (OSError, ValueError, ConnectionError) as error:
        print(f"Server error: {error}")