from src.crypto.x25519 import (
    BASE_POINT,
    generate_private_key,
    public_key_from_private,
    shared_secret,
    x25519,
)


def test_x25519_alice_public_key_vector():
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    expected_public = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )

    assert x25519(alice_private, BASE_POINT) == expected_public


def test_x25519_bob_public_key_vector():
    bob_private = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )

    expected_public = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )

    assert x25519(bob_private, BASE_POINT) == expected_public


def test_x25519_shared_secret_vector():
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    bob_private = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )

    alice_public = public_key_from_private(alice_private)
    bob_public = public_key_from_private(bob_private)

    alice_secret = shared_secret(alice_private, bob_public)
    bob_secret = shared_secret(bob_private, alice_public)

    expected_secret = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )

    assert alice_secret == expected_secret
    assert bob_secret == expected_secret
    assert alice_secret == bob_secret


def test_x25519_generated_keys_create_same_secret():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key_from_private(alice_private)
    bob_public = public_key_from_private(bob_private)

    alice_secret = shared_secret(alice_private, bob_public)
    bob_secret = shared_secret(bob_private, alice_public)

    assert len(alice_public) == 32
    assert len(bob_public) == 32
    assert len(alice_secret) == 32
    assert alice_secret == bob_secret