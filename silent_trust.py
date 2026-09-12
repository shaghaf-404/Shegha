"""
silent_trust.py — Passive liveness authentication for branch-to-branch links
=============================================================================
Concept: "Silent Trust" — a branch proves identity not by responding to
challenges, but by proactively sending periodic signed heartbeats.
Silence (missing heartbeat) = untrusted. No reply is ever sent.

Used ONLY between company branches. Clients use NTRU challenge-response.

Inspired by: BFD (RFC 5880), IPSec Dead Peer Detection (RFC 3706)
"""

import json
import socket
import struct
import threading
import time
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto.ca import sign_data, verify_signature, CA_PUBLIC_KEY, CA_KEYPAIR

# ── Configuration ─────────────────────────────────────────────────────────────
HB_INTERVAL   = 30     # seconds between heartbeats
HB_MISS_WARN  = 1      # missed windows before SUSPICIOUS
HB_MISS_BLOCK = 3      # missed windows before BLOCKED
HB_PORT       = 5500   # dedicated port, separate from main chat port

# ── Trust states ─────────────────────────────────────────────────────────────
TRUSTED    = "TRUSTED"
SUSPICIOUS = "SUSPICIOUS"
BLOCKED    = "BLOCKED"


class SilentTrustMonitor:
    """
    Runs on each branch. Tracks the liveness state of every peer branch.
    Sends its own signed heartbeats and silently verifies incoming ones.
    """

    def __init__(self, branch_id: str, keypair, peer_certs: dict,
                 hb_port: int = HB_PORT,
                 hb_interval: int = HB_INTERVAL,
                 hb_miss_warn: int = HB_MISS_WARN,
                 hb_miss_block: int = HB_MISS_BLOCK):
        """
        branch_id    : e.g. "branch_a"
        keypair      : ElGamalKeyPair — this branch's signing key (CA-issued)
        peer_certs   : { peer_id: certificate_dict } — CA-verified certs of peers
        hb_port      : TCP port for heartbeat traffic (default 5500)
        hb_interval  : seconds between heartbeats (default 30)
        """
        self.branch_id    = branch_id
        self.keypair      = keypair
        self.peer_certs   = peer_certs
        self.hb_port      = hb_port
        self.hb_interval  = hb_interval
        self.hb_miss_warn  = hb_miss_warn
        self.hb_miss_block = hb_miss_block

        self._seq        = 0
        self._seq_lock   = threading.Lock()

        # { peer_id: {"last_seen": float, "last_seq": int, "state": str, "misses": int} }
        self._peers      = {}
        self._peers_lock = threading.Lock()

        # { peer_id: (host, hb_port) } — updated dynamically via add_peer()
        self._peer_addresses      = {}
        self._peer_addresses_lock = threading.Lock()

        self._wakeup_sender       = threading.Event()

        # initialize state for known peers
        for pid in peer_certs:
            self._peers[pid] = {
                "last_seen": 0.0,
                "last_seq":  -1,
                "state":     BLOCKED,   # untrusted until first HB received
                "misses":    hb_miss_block,
            }

    # ── Packet building ───────────────────────────────────────────────────────

    def _make_heartbeat(self) -> bytes:
        with self._seq_lock:
            self._seq += 1
            seq = self._seq

        payload = {
            "from":      self.branch_id,
            "seq":       seq,
            "timestamp": int(time.time()),
        }
        data_bytes = json.dumps(payload, sort_keys=True).encode()
        r, s = sign_data(data_bytes, self.keypair)
        payload["sig_r"] = r
        payload["sig_s"] = s
        return json.dumps(payload).encode()

    # ── Packet verification ───────────────────────────────────────────────────

    def _verify_heartbeat(self, raw: bytes) -> bool:
        """
        Verify and process an incoming heartbeat. Returns True if valid.
        Never sends a reply — silent by design.
        """
        try:
            pkt = json.loads(raw.decode())
            peer_id = pkt["from"]
            seq     = pkt["seq"]
            ts      = pkt["timestamp"]
            r, s    = pkt["sig_r"], pkt["sig_s"]
        except (KeyError, ValueError, json.JSONDecodeError):
            return False

        # Reject unknown peers silently — no need to log noise
        if peer_id not in self.peer_certs:
            return False

        # Replay guard: timestamp must be within ±2 × hb_interval of now
        now = time.time()
        if abs(now - ts) > 2 * self.hb_interval:
            print(f"[SilentTrust] Stale heartbeat from {peer_id!r} — rejected")
            return False

        # Verify ElGamal signature
        cert     = self.peer_certs[peer_id]
        peer_pub = cert["data"]["public_key"]
        payload_to_verify = json.dumps(
            {"from": peer_id, "seq": seq, "timestamp": ts},
            sort_keys=True
        ).encode()
        if not verify_signature(payload_to_verify, (r, s), peer_pub):
            print(f"[SilentTrust] BAD signature from {peer_id!r} — rejected")
            return False

        # Sequence guard: reject replayed or out-of-order packets
        with self._peers_lock:
            peer = self._peers.get(peer_id)
            if peer is None:
                return False
            if seq <= peer["last_seq"]:
                print(f"[SilentTrust] Replayed seq {seq} from {peer_id!r} — rejected")
                return False

            # All checks passed — update state silently
            peer["last_seen"] = now
            peer["last_seq"]  = seq
            peer["misses"]    = 0
            old_state = peer["state"]
            peer["state"] = TRUSTED

        if old_state != TRUSTED:
            print(f"[SilentTrust] {peer_id!r} → TRUSTED  (seq={seq})")
        return True

    # ── Watchdog: detect missing heartbeats ───────────────────────────────────

    def _watchdog(self):
        """Runs in background. Degrades trust state when heartbeats stop."""
        while True:
            time.sleep(self.hb_interval)
            now = time.time()
            with self._peers_lock:
                for pid, peer in self._peers.items():
                    age = now - peer["last_seen"]
                    if age > self.hb_interval:
                        peer["misses"] += 1
                        if peer["misses"] >= self.hb_miss_block:
                            new_state = BLOCKED
                        elif peer["misses"] >= self.hb_miss_warn:
                            new_state = SUSPICIOUS
                        else:
                            new_state = peer["state"]

                        if new_state != peer["state"]:
                            print(f"[SilentTrust] {pid!r} → {new_state} "
                                  f"(missed {peer['misses']} windows)")
                            peer["state"] = new_state

    # ── Sender: broadcast heartbeats ─────────────────────────────────────────

    def _sender(self):
        """Send a signed heartbeat to all known branch peers every hb_interval."""
        while True:
            hb = self._make_heartbeat()
            framed = struct.pack('>I', len(hb)) + hb
            with self._peer_addresses_lock:
                targets = list(self._peer_addresses.items())
            for pid, (host, port) in targets:
                try:
                    with socket.create_connection((host, port), timeout=5) as s:
                        s.sendall(framed)
                except OSError:
                    pass   # will be caught by watchdog
            self._wakeup_sender.wait(self.hb_interval)
            self._wakeup_sender.clear()

    # ── Receiver: listen for incoming heartbeats ──────────────────────────────

    def _receiver(self):
        """Listen on self.hb_port. Verify each packet silently. Never reply."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', self.hb_port))
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            threading.Thread(
                target=self._handle_incoming, args=(conn,), daemon=True
            ).start()

    def _handle_incoming(self, conn):
        try:
            # Read 4-byte length header
            length_b = b""
            while len(length_b) < 4:
                chunk = conn.recv(4 - len(length_b))
                if not chunk:
                    return
                length_b += chunk
            length = struct.unpack('>I', length_b)[0]
            if length > 65536:          # sanity cap
                return
            # Read exactly `length` bytes of payload
            raw = b""
            while len(raw) < length:
                chunk = conn.recv(length - len(raw))
                if not chunk:
                    return
                raw += chunk
            self._verify_heartbeat(raw)   # silent — no reply sent
        except OSError:
            pass
        finally:
            conn.close()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, peer_addresses: dict = None):
        """
        Launch all background threads.
        peer_addresses: { peer_id: (host, hb_port) }  — can be empty or None;
                        peers added later via add_peer() will be picked up automatically.
        """
        if peer_addresses:
            with self._peer_addresses_lock:
                self._peer_addresses.update(peer_addresses)
            with self._peers_lock:
                for pid in peer_addresses:
                    if pid not in self._peers:
                        self._peers[pid] = {
                            "last_seen": 0.0,
                            "last_seq":  -1,
                            "state":     BLOCKED,
                            "misses":    self.hb_miss_block,
                        }
        threading.Thread(target=self._receiver, daemon=True).start()
        threading.Thread(target=self._watchdog, daemon=True).start()
        threading.Thread(target=self._sender,   daemon=True).start()
        print(f"[SilentTrust] Started for branch {self.branch_id!r}")

    def add_peer(self, peer_id: str, cert: dict, host: str, hb_port: int) -> None:
        """
        Register a new peer from the UDP discovery listener.
        If the peer already exists but has a NEW certificate (e.g. it restarted
        and generated a new key pair), its state is reset to BLOCKED to 
        re-establish trust with the new key.
        """
        is_new = False
        is_updated = False
        with self._peers_lock:
            if peer_id in self._peers:
                # Peer exists. Check if certificate changed.
                old_cert = self.peer_certs.get(peer_id, {})
                if old_cert.get("data", {}).get("public_key") != cert.get("data", {}).get("public_key"):
                    is_updated = True
                    self._peers[peer_id] = {
                        "last_seen": 0.0,
                        "last_seq":  -1,
                        "state":     BLOCKED,
                        "misses":    self.hb_miss_block,
                    }
                else:
                    return  # Existing peer, unchanged certificate -> idempotent ignore
            else:
                is_new = True
                self._peers[peer_id] = {
                    "last_seen": 0.0,
                    "last_seq":  -1,
                    "state":     BLOCKED,
                    "misses":    self.hb_miss_block,
                }
                
        self.peer_certs[peer_id] = cert
        with self._peer_addresses_lock:
            self._peer_addresses[peer_id] = (host, hb_port)
            
        self._wakeup_sender.set()
        
        if is_new:
            print(f"[SilentTrust] Peer {peer_id!r} registered — heartbeats → {host}:{hb_port}")
        elif is_updated:
            print(f"[SilentTrust] Peer {peer_id!r} certificate updated (restarted) — state reset to BLOCKED")

    def is_trusted(self, peer_id: str) -> bool:
        """Returns True only if the peer's heartbeats are current and valid."""
        with self._peers_lock:
            peer = self._peers.get(peer_id)
            return peer is not None and peer["state"] == TRUSTED

    def get_state(self, peer_id: str) -> str:
        with self._peers_lock:
            peer = self._peers.get(peer_id)
            return peer["state"] if peer else BLOCKED

    def status(self) -> dict:
        """Return full trust status of all peers (for logging/reporting)."""
        with self._peers_lock:
            return {
                pid: {
                    "state":     p["state"],
                    "misses":    p["misses"],
                    "last_seen": p["last_seen"],
                }
                for pid, p in self._peers.items()
            }