"""
=============================================================================
Proteus-SMC — client/chat.py
=============================================================================
Interface de messagerie chiffrée entre deux processus via SMCCipher.

Utilisation :
  # Terminal 1 — côté serveur
  python client/chat.py listen --port 5000

  # Terminal 2 — côté client
  python client/chat.py connect --port 5000
  # ou depuis une autre machine :
  python client/chat.py connect --host 192.168.1.42 --port 5000

Le handshake ECDH (X25519) est réalisé automatiquement à la connexion.
Les deux terminaux affichent la même empreinte de session pour confirmer
l'intégrité du canal établi.
=============================================================================
"""

import argparse
import socket
import struct
import sys
import threading
from pathlib import Path

# ── Résolution des chemins ───────────────────────────────────────────────────

_ROOT   = Path(__file__).resolve().parent.parent
_CLIENT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT / "src"))     # proteus_smc package
sys.path.insert(0, str(_CLIENT))           # handshake module

from handshake import handshake_initiator, handshake_responder
from proteus_smc import SMCCipher


# ── Framing réseau des messages chiffrés ────────────────────────────────────
# Format : [ longueur ciphertext (uint32 BE) | ciphertext ]

def _send_msg(sock: socket.socket, cipher: SMCCipher, text: str) -> None:
    ct = cipher.encrypt(text.encode("utf-8"))
    sock.sendall(struct.pack(">I", len(ct)) + ct)


def _recv_msg(sock: socket.socket, cipher: SMCCipher) -> str | None:
    raw = _recv_exact(sock, 4)
    if raw is None:
        return None
    length = struct.unpack(">I", raw)[0]
    ct = _recv_exact(sock, length)
    if ct is None:
        return None
    return cipher.decrypt(ct).decode("utf-8")


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ── Boucle de réception (thread dédié) ──────────────────────────────────────

def _receive_loop(
    sock: socket.socket,
    cipher: SMCCipher,
    peer_label: str,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            msg = _recv_msg(sock, cipher)
            if msg is None:
                print("\n[SMC] Connexion fermée par le pair.")
                stop.set()
                break
            # Efface la ligne "> " en cours, affiche le message, réaffiche le prompt
            print(f"\r\033[K[{peer_label}] {msg}\n> ", end="", flush=True)
        except OSError:
            if not stop.is_set():
                print("\n[SMC] Connexion interrompue.")
            stop.set()
            break
        except Exception as exc:
            if not stop.is_set():
                print(f"\n[SMC] Erreur réception : {exc}")
            stop.set()
            break


# ── Boucle principale de messagerie ─────────────────────────────────────────

def _chat_loop(sock: socket.socket, cipher: SMCCipher, peer_label: str) -> None:
    stop = threading.Event()
    rx_thread = threading.Thread(
        target=_receive_loop,
        args=(sock, cipher, peer_label, stop),
        daemon=True,
    )
    rx_thread.start()

    try:
        while not stop.is_set():
            print("> ", end="", flush=True)
            line = sys.stdin.readline()
            if not line:          # EOF (Ctrl+D)
                break
            if stop.is_set():
                break
            text = line.rstrip("\n")
            if text:
                try:
                    _send_msg(sock, cipher, text)
                except OSError:
                    print("[SMC] Impossible d'envoyer : connexion perdue.")
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sock.close()


# ── Établissement de la connexion et handshake ───────────────────────────────

def _run_listen(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    print(f"[SMC] En écoute sur le port {port}")
    print(f"[SMC] Session ID : {port}  (partagez ce numéro avec votre pair)")
    print("[SMC] En attente de connexion...\n")

    conn, addr = srv.accept()
    srv.close()
    peer_label = f"{addr[0]}:{addr[1]}"
    print(f"[SMC] Connexion de {peer_label}")

    print("[SMC] Handshake ECDH (X25519)...")
    session_key, session_seed, fingerprint = handshake_responder(conn)

    print(f"[SMC] ✓ Session établie")
    print(f"[SMC] Empreinte    : {fingerprint}")
    print("[SMC] Vérifiez que votre pair affiche la même empreinte.")
    print("[SMC] Tapez vos messages. Ctrl+C ou Ctrl+D pour quitter.\n")

    cipher = SMCCipher(key=session_key, seed=session_seed)
    _chat_loop(conn, cipher, peer_label)


def _run_connect(host: str, port: int) -> None:
    print(f"[SMC] Connexion à {host}:{port}...")
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    peer_label = f"{host}:{port}"

    print("[SMC] Handshake ECDH (X25519)...")
    session_key, session_seed, fingerprint = handshake_initiator(conn)

    print(f"[SMC] ✓ Session établie")
    print(f"[SMC] Empreinte    : {fingerprint}")
    print("[SMC] Vérifiez que votre pair affiche la même empreinte.")
    print("[SMC] Tapez vos messages. Ctrl+C ou Ctrl+D pour quitter.\n")

    cipher = SMCCipher(key=session_key, seed=session_seed)
    _chat_loop(conn, cipher, peer_label)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="chat.py",
        description="Proteus-SMC : messagerie chiffrée point-à-point",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    p_listen = sub.add_parser("listen", help="Attend une connexion entrante")
    p_listen.add_argument(
        "--port", type=int, default=51820,
        help="Port d'écoute (défaut : 51820)",
    )

    p_connect = sub.add_parser("connect", help="Se connecte à un pair en écoute")
    p_connect.add_argument(
        "--host", default="127.0.0.1",
        help="Adresse du pair (défaut : 127.0.0.1)",
    )
    p_connect.add_argument(
        "--port", type=int, default=51820,
        help="Port du pair (défaut : 51820)",
    )

    args = parser.parse_args()

    try:
        if args.mode == "listen":
            _run_listen(args.port)
        else:
            _run_connect(args.host, args.port)
    except ConnectionRefusedError:
        print(f"[SMC] Erreur : aucun pair en écoute sur ce port.")
        sys.exit(1)
    except ValueError as exc:
        print(f"[SMC] Handshake échoué : {exc}")
        sys.exit(1)

    print("\n[SMC] Session terminée.")


if __name__ == "__main__":
    main()
