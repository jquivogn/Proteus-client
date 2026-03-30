"""
=============================================================================
Proteus-SMC — web/app.py
=============================================================================
Flask-SocketIO server that manages a real TCP connection between Alice and Bob
using the SMC protocol.  A single browser tab drives both sides.

Architecture:
  Browser  ──SocketIO──►  Flask app
                              ├── Alice: listens on 127.0.0.1:PORT  (responder)
                              └── Bob:   connects to 127.0.0.1:PORT (initiator)

Each side gets an SMCCipher derived from the X25519 ECDH handshake.
Four threads: main, SocketIO handler, alice-receiver, bob-receiver.
=============================================================================
"""

import sys
import socket
import struct
import threading
from pathlib import Path

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

# ── Path setup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent          # Proteus-client/
sys.path.insert(0, str(_ROOT.parent / "Proteus" / "src"))  # proteus_smc
sys.path.insert(0, str(_ROOT))                          # handshake

from handshake import handshake_initiator, handshake_responder  # noqa: E402
from proteus_smc import SMCCipher                               # noqa: E402

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = "proteus-demo-secret"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# sid -> {alice_sock, bob_sock, alice_cipher, bob_cipher, alice_lock, bob_lock}
_sessions: dict = {}
_sessions_lock = threading.Lock()


# ── TCP framing helpers ──────────────────────────────────────────────────────
# Format: [ uint32 BE length | ciphertext ]  (matches chat.py)

def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_framed(sock: socket.socket) -> bytes | None:
    raw = _recv_exact(sock, 4)
    if raw is None:
        return None
    n = struct.unpack(">I", raw)[0]
    return _recv_exact(sock, n)


# ── Receiver thread ──────────────────────────────────────────────────────────

def _recv_loop(
    sock: socket.socket,
    cipher: "SMCCipher",
    lock: threading.Lock,
    recipient: str,
    sid: str,
) -> None:
    """Read encrypted frames, decrypt, emit plaintext to the browser."""
    while True:
        try:
            ct = _recv_framed(sock)
            if ct is None:
                break
            with lock:
                plaintext = cipher.decrypt(ct).decode("utf-8")
            socketio.emit(
                "message_received",
                {"to": recipient, "plaintext": plaintext},
                to=sid,
            )
        except Exception:
            break


# ── Session initialisation (runs in a background thread) ────────────────────

def _init_session(sid: str) -> None:
    """
    1. Open a server socket (Alice listens).
    2. Thread A: accept + handshake_responder  → alice_conn
    3. Thread B: connect + handshake_initiator → bob_sock
    4. Build two SMCCipher instances, start receiver threads.
    5. Emit session_ready to the browser.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    result: dict = {}

    def alice_fn() -> None:
        try:
            conn, _ = srv.accept()
            srv.close()
            key, seed, fp = handshake_responder(conn)
            result.update(alice_sock=conn, key=key, seed=seed, fp=fp)
        except Exception as exc:
            result.setdefault("error", str(exc))

    def bob_fn() -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            handshake_initiator(s)          # keys identical; discard duplicate
            result["bob_sock"] = s
        except Exception as exc:
            result.setdefault("error", str(exc))

    t_alice = threading.Thread(target=alice_fn, daemon=True)
    t_bob = threading.Thread(target=bob_fn, daemon=True)
    t_alice.start()
    t_bob.start()
    t_alice.join(timeout=30)
    t_bob.join(timeout=30)

    if "error" in result or "alice_sock" not in result or "bob_sock" not in result:
        socketio.emit(
            "session_error",
            {"error": result.get("error", "Handshake timeout")},
            to=sid,
        )
        return

    alice_cipher = SMCCipher(key=result["key"], seed=result["seed"])
    bob_cipher   = SMCCipher(key=result["key"], seed=result["seed"])
    alice_lock   = threading.Lock()
    bob_lock     = threading.Lock()

    with _sessions_lock:
        _sessions[sid] = {
            "alice_sock":   result["alice_sock"],
            "bob_sock":     result["bob_sock"],
            "alice_cipher": alice_cipher,
            "bob_cipher":   bob_cipher,
            "alice_lock":   alice_lock,
            "bob_lock":     bob_lock,
        }

    # Receiver threads
    # alice_recv_loop reads from alice_conn → decrypts with alice_cipher
    #   (receives messages that Bob sent)
    # bob_recv_loop reads from bob_sock → decrypts with bob_cipher
    #   (receives messages that Alice sent)
    threading.Thread(
        target=_recv_loop,
        args=(result["alice_sock"], alice_cipher, alice_lock, "alice", sid),
        daemon=True,
    ).start()
    threading.Thread(
        target=_recv_loop,
        args=(result["bob_sock"], bob_cipher, bob_lock, "bob", sid),
        daemon=True,
    ).start()

    socketio.emit("session_ready", {"fingerprint": result["fp"]}, to=sid)


# ── Flask routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── SocketIO event handlers ──────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    sid = request.sid
    threading.Thread(target=_init_session, args=(sid,), daemon=True).start()


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    with _sessions_lock:
        sess = _sessions.pop(sid, None)
    if sess:
        for key in ("alice_sock", "bob_sock"):
            try:
                sess[key].close()
            except Exception:
                pass


@socketio.on("send_message")
def on_send_message(data: dict) -> None:
    sid = request.sid
    with _sessions_lock:
        sess = _sessions.get(sid)
    if not sess:
        return

    sender = data.get("from", "")
    text   = data.get("text", "").strip()
    if not text:
        return

    if sender == "alice":
        with sess["alice_lock"]:
            ct = sess["alice_cipher"].encrypt(text.encode("utf-8"))
        _send_framed(sess["alice_sock"], ct)
        emit("message_sent", {
            "from":       "alice",
            "ciphertext": ct.hex(),
            "plaintext":  text,
        })

    elif sender == "bob":
        with sess["bob_lock"]:
            ct = sess["bob_cipher"].encrypt(text.encode("utf-8"))
        _send_framed(sess["bob_sock"], ct)
        emit("message_sent", {
            "from":       "bob",
            "ciphertext": ct.hex(),
            "plaintext":  text,
        })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[SMC] Starting Proteus-SMC web demo on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5042, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
