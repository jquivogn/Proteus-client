"""
=============================================================================
Proteus-SMC — client/handshake.py
=============================================================================
Protocole de handshake ECDH (X25519) suivant la proposition.

Flux de messages :
  Alice  ──[HELLO]──────────►  Bob
  Alice  ◄─[HELLO_ACK]───────  Bob
  Alice  ──[ACK_CONFIRM]─────►  Bob

Dérivation :
  shared_dh               = X25519(priv_self, pub_other)
  material (48B)          = PBKDF2-SHA256(shared_dh, nonce_A ∥ nonce_B ∥ b"proteus-smc-hs")
  session_key  (32B)      = material[:32]
  session_seed (16B)      = material[32:]
  fingerprint             = SHA256(session_seed)[:16].hex()
=============================================================================
"""

import hashlib
import hmac
import secrets
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ── Types de messages ────────────────────────────────────────────────────────

MSG_HELLO       = 0x01   # 1B type + 32B nonce + 32B pub  = 65B
MSG_HELLO_ACK   = 0x02   # 1B type + 32B nonce + 32B pub  = 65B
MSG_ACK_CONFIRM = 0x03   # 1B type + 16B verify_tag        = 17B


# ── Framing réseau (longueur préfixée, uint32 big-endian) ────────────────────

def _send(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée pendant le handshake")
        buf.extend(chunk)
    return bytes(buf)


# ── Cryptographie du handshake ───────────────────────────────────────────────

def _derive_material(shared_dh: bytes, nonce_a: bytes, nonce_b: bytes) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256",
        password=shared_dh,
        salt=nonce_a + nonce_b + b"proteus-smc-hs",
        iterations=100_000,
        dklen=48,
    )
    return material[:32], material[32:]   # session_key (32B), session_seed (16B)


def _compute_verify_tag(session_key: bytes, nonce_a: bytes, nonce_b: bytes) -> bytes:
    return hmac.new(
        session_key,
        b"handshake-confirm" + nonce_a + nonce_b,
        hashlib.sha256,
    ).digest()[:16]


def _fingerprint(session_seed: bytes) -> str:
    return hashlib.sha256(session_seed).hexdigest()[:16]


# ── Rôles ────────────────────────────────────────────────────────────────────

def handshake_initiator(sock) -> tuple[bytes, bytes, str]:
    """
    Rôle Alice (initiateur) :
      1. Envoie HELLO  (nonce_A, pub_A)
      2. Reçoit HELLO_ACK (nonce_B, pub_B)
      3. Dérive session_key / session_seed
      4. Envoie ACK_CONFIRM (verify_tag)
    Retourne (session_key, session_seed, fingerprint).
    """
    priv_a  = X25519PrivateKey.generate()
    pub_a   = priv_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce_a = secrets.token_bytes(32)

    _send(sock, bytes([MSG_HELLO]) + nonce_a + pub_a)

    raw = _recv(sock)
    if len(raw) != 65 or raw[0] != MSG_HELLO_ACK:
        raise ValueError(f"HELLO_ACK invalide (reçu {len(raw)}B, type={raw[0]:#x})")
    nonce_b = raw[1:33]
    pub_b   = raw[33:65]

    shared_dh = priv_a.exchange(X25519PublicKey.from_public_bytes(pub_b))
    session_key, session_seed = _derive_material(shared_dh, nonce_a, nonce_b)

    tag = _compute_verify_tag(session_key, nonce_a, nonce_b)
    _send(sock, bytes([MSG_ACK_CONFIRM]) + tag)

    return session_key, session_seed, _fingerprint(session_seed)


def handshake_responder(sock) -> tuple[bytes, bytes, str]:
    """
    Rôle Bob (répondeur) :
      1. Reçoit HELLO (nonce_A, pub_A)
      2. Envoie HELLO_ACK (nonce_B, pub_B)
      3. Dérive session_key / session_seed
      4. Reçoit et vérifie ACK_CONFIRM
    Retourne (session_key, session_seed, fingerprint).
    """
    raw = _recv(sock)
    if len(raw) != 65 or raw[0] != MSG_HELLO:
        raise ValueError(f"HELLO invalide (reçu {len(raw)}B, type={raw[0]:#x})")
    nonce_a = raw[1:33]
    pub_a   = raw[33:65]

    priv_b  = X25519PrivateKey.generate()
    pub_b   = priv_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce_b = secrets.token_bytes(32)

    _send(sock, bytes([MSG_HELLO_ACK]) + nonce_b + pub_b)

    shared_dh = priv_b.exchange(X25519PublicKey.from_public_bytes(pub_a))
    session_key, session_seed = _derive_material(shared_dh, nonce_a, nonce_b)

    raw_confirm = _recv(sock)
    if len(raw_confirm) != 17 or raw_confirm[0] != MSG_ACK_CONFIRM:
        raise ValueError(f"ACK_CONFIRM invalide (reçu {len(raw_confirm)}B)")

    expected_tag = _compute_verify_tag(session_key, nonce_a, nonce_b)
    received_tag = raw_confirm[1:17]

    if not hmac.compare_digest(expected_tag, received_tag):
        raise ValueError("verify_tag invalide — attaque Man-in-the-Middle possible")

    return session_key, session_seed, _fingerprint(session_seed)
