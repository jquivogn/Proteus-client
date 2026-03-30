"use strict";

const socket = io();

// ── DOM refs ──────────────────────────────────────────────────────────────
const overlay         = document.getElementById("overlay");
const fingerprintEl   = document.getElementById("fingerprint");
const aliceMessages   = document.getElementById("alice-messages");
const bobMessages     = document.getElementById("bob-messages");
const ctFeed          = document.getElementById("ct-feed");
const aliceInput      = document.getElementById("alice-input");
const bobInput        = document.getElementById("bob-input");

// ── Helpers ────────────────────────────────────────────────────────────────

/** Append a chat bubble to the given message list and scroll to bottom. */
function addBubble(container, text, cls) {
  const div = document.createElement("div");
  div.className = `bubble ${cls}`;
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

/**
 * Split a SMCCipher hex string into coloured <span> segments.
 * Format: MAGIC(3) VERSION(1) N_BLOCKS(4) CHECKSUM(4) IV(16) ROUND_META(2*n) CT
 * All sizes are in bytes; each byte = 2 hex chars.
 */
function colorizeHex(h) {
  if (h.length < 56) return `<span class="ch-ct">${h}</span>`;
  const nBlocks = parseInt(h.slice(8, 16), 16);
  const metaEnd = 56 + nBlocks * 4;          // 56 = (3+1+4+4+16)*2
  return (
    `<span class="ch-magic">${h.slice(0, 6)}</span>`      +  // 3 B
    `<span class="ch-version">${h.slice(6, 8)}</span>`    +  // 1 B
    `<span class="ch-nblocks">${h.slice(8, 16)}</span>`   +  // 4 B
    `<span class="ch-checksum">${h.slice(16, 24)}</span>` +  // 4 B
    `<span class="ch-iv">${h.slice(24, 56)}</span>`       +  // 16 B
    `<span class="ch-meta">${h.slice(56, metaEnd)}</span>` + // 2*n B
    `<span class="ch-ct">${h.slice(metaEnd)}</span>`         // rest
  );
}

/** Append a line to the console. */
function addCiphertext(from, hexStr) {
  // Remove the placeholder on first entry
  const empty = ctFeed.querySelector(".console-empty");
  if (empty) empty.remove();

  const time = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const dir  = from === "alice" ? "alice → bob  " : "bob   → alice";

  const line = document.createElement("div");
  line.className = "console-line";
  line.innerHTML =
    `<span class="cl-time">${time}</span>` +
    `<span class="cl-dir ${from}">${dir}</span>` +
    `<span class="cl-hex">${colorizeHex(hexStr)}</span>`;

  ctFeed.appendChild(line);
  ctFeed.scrollTop = ctFeed.scrollHeight;
}

// ── SocketIO events ────────────────────────────────────────────────────────

socket.on("connect", () => {
  fingerprintEl.textContent = "connecting…";
});

socket.on("session_ready", (data) => {
  fingerprintEl.textContent = data.fingerprint;
  overlay.classList.add("hidden");
});

socket.on("session_error", (data) => {
  fingerprintEl.textContent = "error";
  overlay.innerHTML = `<p style="color:#ef4444">Handshake failed: ${data.error}</p>`;
});

/**
 * Fired after WE sent a message.
 * - Add "sent" bubble in the sender's panel.
 * - Add ciphertext in the centre column.
 * (The receiver thread on the server will fire message_received for the
 *  other panel once the decrypted bytes come off the wire.)
 */
socket.on("message_sent", (data) => {
  const { from, plaintext, ciphertext } = data;
  if (from === "alice") {
    addBubble(aliceMessages, plaintext, "sent");
  } else {
    addBubble(bobMessages, plaintext, "sent");
  }
  addCiphertext(from, ciphertext);
});

/**
 * Fired by a receiver thread — the decrypted message arrived on the wire.
 * - Add a "received" bubble in the recipient's panel.
 */
socket.on("message_received", (data) => {
  const { to, plaintext } = data;
  if (to === "alice") {
    addBubble(aliceMessages, plaintext, "received");
  } else {
    addBubble(bobMessages, plaintext, "received");
  }
});

// ── Send ──────────────────────────────────────────────────────────────────

function sendMessage(who) {
  const input = who === "alice" ? aliceInput : bobInput;
  const text  = input.value.trim();
  if (!text) return;
  socket.emit("send_message", { from: who, text });
  input.value = "";
  input.focus();
}

// Enter key support
aliceInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendMessage("alice");
});
bobInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendMessage("bob");
});
