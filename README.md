# secure-channel
Final project for ENCS4320 Applied Cryptography: SecureChannel
## Overview

SecureChannel is a client-server application that creates a secure communication channel over TCP.

It uses:

* X25519 for ephemeral key exchange
* HMAC-SHA256 with a pre-shared key for authentication
* HKDF-SHA256 for deriving session keys
* ChaCha20-Poly1305 for authenticated encryption
* Sequence numbers to prevent replay attacks
## Requirements

* Python 3
* pytest for running the test suite

All cryptographic primitives are implemented from scratch without using external cryptography libraries.
## Running the Tests

Run the complete test suite from the project directory:

```bash
pytest tests
```

The test suite verifies the cryptographic primitives, handshake, secure channel, packet format, and TCP transport.
## Running the Server

From the project directory, run:

```bash
python -m src.apps.server
```

The server listens for one client and starts the secure handshake.
## Running the Client

Open another terminal in the project directory and run:

```bash
python -m src.apps.client
```

Enter the same pre-shared key on both the server and client to complete the secure handshake.
## Using the Chat

After the handshake succeeds, the client and server can exchange encrypted text messages.

Type:

```text
/quit
```

to close the connection.
## Project Structure

* `src/crypto/` contains the cryptographic primitives.
* `src/protocol/` contains the handshake, secure channel, packet, and transport logic.
* `src/apps/` contains the client and server programs.
* `tests/` contains the complete test suite.
* `report/` contains the project report.
## Security Features

* Ephemeral X25519 keys provide a new shared secret for every connection.
* The pre-shared key authenticates the handshake using HMAC-SHA256.
* HKDF-SHA256 derives separate keys and nonce values for each direction.
* ChaCha20-Poly1305 protects message confidentiality and integrity.
* Sequence numbers reject repeated or out-of-order messages.
* The message header is authenticated as additional authenticated data.
## Test Results

The complete test suite contains 68 tests.

All tests pass successfully, including official test vectors and tests for tampering, replay attacks, incorrect keys, packet handling, and TCP communication.
## Current Limitations

* The current version supports one client connection at a time.
* The chat supports text messages only.
* Both sides must manually enter the same pre-shared key.
* File transfer and a graphical user interface are not implemented.
