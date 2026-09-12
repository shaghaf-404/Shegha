import errno
import os
import socket
import struct
import sys
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NTRU_KEY_DIR  = PROJECT_ROOT   # all NTRU key files live here; single source of truth
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
import json
import threading
import time
from typing import Optional
from crypto.silent_trust import SilentTrustMonitor, TRUSTED
from crypto.symmetric.rc5     import encrypt_message, decrypt_message
from crypto.symmetric.feistel import feistel_encrypt_bytes, feistel_decrypt_bytes
from crypto.ca      import CertificateAuthority, CA_PUBLIC_KEY, verify_certificate
from crypto.asymmetric.elgamal import (
    # Key generation
    generate_keypair,
    ElGamalKeyPair,
    _P_SMALL, _G_SMALL,   # available for unit-test mode only
    _P_1024,  _G_1024,    # production 1024-bit parameters
    # Crypto operations
    encrypt             as elgamal_encrypt,
    decrypt             as elgamal_decrypt,
    # Session key pipeline
    generate_session_key_bytes,
    session_key_bytes_to_int,
    int_to_session_key_bytes,
    SESSION_KEY_BYTES,
    HANDSHAKE_TIMEOUT,
    # Serialisation
    serialize_public_key,
    deserialize_public_key,
    serialize_ciphertext,
    deserialize_ciphertext,
    # Validation
    _validate_public_key,
    _validate_ciphertext,
)
from crypto.pqc.NTRU import generate_keypair as generate_ntru_keypair, NTRUAuthenticator, Q as NTRU_Q

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
HOST = '0.0.0.0'
try:
    _p = int(os.environ.get("CHAT_PORT", "5000"))
    PORT = _p if 1 <= _p <= 65535 else 5000
except ValueError:
    PORT = 5000
MAX_FILE_BYTES = 1 * 1024 * 1024     # 1 MB plaintext limit per file transfer

# True  → new ElGamal key pair per accepted connection (forward secrecy)
# False → one key pair for the server lifetime
USE_EPHEMERAL_KEYPAIR = False

# Issue 3 fix: USE_SMALL_PRIME must be False in production.
# The small prime (104 723) forces an unsafe modular workaround because a
# 32-byte session key integer (2^256) far exceeds it.  The 1024-bit prime
# (2^1024) always satisfies 1 ≤ m < p without any manipulation.
# Set True ONLY for isolated unit-testing of ElGamal math, never for live chat.
USE_SMALL_PRIME = False   # ← Issue 3 fix: was True

# ─────────────────────────────────────────────────────────────────────────────
# WAN / Cross-network connectivity settings
# ─────────────────────────────────────────────────────────────────────────────
_MAX_CONNECT_RETRIES = 3          # client retry attempts on connection failure
_RETRY_DELAY         = 3          # seconds between retries
_CONNECT_TIMEOUT     = 10         # TCP connect timeout per attempt (seconds)

# Server-side connection info (populated at startup by _display_connection_info)
_server_public_ip: Optional[str] = None
_server_lan_ip:    Optional[str] = None
_server_port:      int           = PORT
_tunnel_url:       Optional[str] = None     # set by /tunnel command (ngrok)


def _resolve_domain(domain: str) -> tuple:
    """Resolve a domain name or validate a raw IP.

    Returns (resolved_ip, display_name, is_domain).
    Raises ValueError on failure.
    """
    import ipaddress as _ipa

    # Already a raw IP?
    try:
        _ipa.ip_address(domain)
        return domain, domain, False
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if not results:
            raise ValueError(f"DNS returned no results for {domain!r}")
        ip = results[0][4][0]
        return ip, domain, True
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve {domain!r} — check the domain name.\n"
            f"  DNS error: {exc}"
        ) from exc


def _get_public_ip() -> str:
    """Fetch the machine's public (WAN) IP via external API."""
    import urllib.request
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Shegha/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode().strip()
                import ipaddress as _ipa
                _ipa.ip_address(ip)          # validate
                return ip
        except Exception:
            continue
    return "<unavailable>"


    if _tunnel_url:
        print(f"  ★ TUNNEL   →  {_tunnel_url}")
        print(f"    (any device on any network can connect using this address)")
    print("═" * 60)
    print()


def _get_all_local_ips() -> list:
    """Return all non-loopback IPv4 addresses assigned to interfaces on this host."""
    ips = []
    try:
        import ctypes
        class struct_sockaddr(ctypes.Structure):
            _fields_ = [('sa_family', ctypes.c_ushort), ('sa_data', ctypes.c_ubyte * 14)]

        class struct_ifaddrs(ctypes.Structure):
            pass

        struct_ifaddrs._fields_ = [
            ('ifa_next', ctypes.POINTER(struct_ifaddrs)),
            ('ifa_name', ctypes.c_char_p),
            ('ifa_flags', ctypes.c_uint),
            ('ifa_addr', ctypes.POINTER(struct_sockaddr)),
            ('ifa_netmask', ctypes.POINTER(struct_sockaddr)),
            ('ifa_ifu', ctypes.c_void_p),
            ('ifa_data', ctypes.c_void_p)
        ]

        libc = ctypes.CDLL('libc.so.6')
        ifaddr = ctypes.POINTER(struct_ifaddrs)()
        if libc.getifaddrs(ctypes.byref(ifaddr)) == 0:
            curr = ifaddr
            while curr:
                if curr.contents.ifa_addr:
                    fam = curr.contents.ifa_addr.contents.sa_family
                    if fam == socket.AF_INET:
                        data = bytes(curr.contents.ifa_addr.contents.sa_data)
                        ip = socket.inet_ntoa(data[2:6])
                        name = curr.contents.ifa_name.decode('utf-8', errors='replace')
                        if not ip.startswith('127.'):
                            ips.append((name, ip))
                curr = curr.contents.ifa_next
            libc.freeifaddrs(ifaddr)
    except Exception:
        pass

    if not ips:
        ips.append(("lan", _get_local_ip()))

    return ips


def _display_connection_info(port: int, label: str = "Server") -> None:
    """Detect and print WAN/LAN connection info so clients know where to connect."""
    global _server_public_ip, _server_lan_ip, _server_port

    _server_port   = port
    _server_lan_ip = _get_local_ip()

    print(f"\n[{label}] Detecting public IP …", end=" ", flush=True)
    _server_public_ip = _get_public_ip()
    print(_server_public_ip)

    all_ips = _get_all_local_ips()

    print()
    print("═" * 60)
    print(f"  {label} — Client Connection Info")
    print("─" * 60)
    print(f"  Local / Subnet Interfaces:")
    for ifname, ifip in all_ips:
        print(f"    • {ifip}:{port:<6} ({ifname})")
    if _server_public_ip != "<unavailable>":
        print(f"  WAN clients  →  {_server_public_ip}:{port}")
        print(f"  (requires port {port}/TCP forwarded on your router)")
    else:
        print(f"  WAN clients  →  set up port forwarding for port {port}/TCP")
    print(f"  Domain name  →  point an A record to the public IP above")
    if _tunnel_url:
        print(f"  ★ TUNNEL   →  {_tunnel_url}")
        print(f"    (any device on any network can connect using this address)")
    print("═" * 60)
    print()


def _start_tunnel(port: int) -> Optional[str]:
    """Start a free TCP tunnel to expose the server port publicly to any network.

    Uses `bore` (zero-config, no credit card, no account required) if available,
    falling back to `pyngrok`.
    """
    global _tunnel_url
    import subprocess, re, shutil

    # 1. Try bore (zero signup, zero card required)
    project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    bore_bin = os.path.join(project_dir, 'bore')
    if not os.path.exists(bore_bin):
        bore_bin = shutil.which('bore')

    if bore_bin and os.path.exists(bore_bin):
        try:
            print(f"[Tunnel] Opening zero-config TCP tunnel via bore to port {port} …")
            proc = subprocess.Popen(
                [bore_bin, 'local', str(port), '--to', 'bore.pub'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            r_port = None
            for _ in range(50):
                line = proc.stdout.readline()
                if not line:
                    break
                match = re.search(r'listening at bore\.pub:(\d+)', line)
                if match:
                    r_port = match.group(1)
                    break
            if r_port:
                _tunnel_url = f"bore.pub:{r_port}"
                print(f"[Tunnel] ✔ Bore TCP Tunnel Active!")
                print(f"[Tunnel]   Clients connect with:")
                print(f"[Tunnel]     Domain name (or IP): bore.pub")
                print(f"[Tunnel]     Server port:         {r_port}")
                return _tunnel_url
        except Exception as exc:
            print(f"[Tunnel] Bore tunnel error: {exc}")

    # 2. Fallback to ngrok
    try:
        from pyngrok import ngrok, conf
        conf.get_default().log_event_callback = lambda log: None
        print(f"[Tunnel] Opening ngrok TCP tunnel to port {port} …")
        tunnel = ngrok.connect(port, "tcp")
        _tunnel_url = tunnel.public_url
        print(f"[Tunnel] ✔ Tunnel active: {_tunnel_url}")
        print(f"[Tunnel]   Clients connect with:")
        addr = _tunnel_url.replace("tcp://", "")
        parts = addr.rsplit(":", 1)
        if len(parts) == 2:
            print(f"[Tunnel]     Domain name (or IP): {parts[0]}")
            print(f"[Tunnel]     Server port:         {parts[1]}")
        return _tunnel_url
    except Exception as exc:
        print(f"[Tunnel] ✗ Failed to open tunnel: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Packet type constants
# ─────────────────────────────────────────────────────────────────────────────
CLIENT_HELLO        = 0x00
SERVER_PUBLIC_KEY   = 0x01
SESSION_KEY_CT      = 0x02
SESSION_ESTABLISHED = 0x03
AUTH_CHALLENGE      = 0x04   # server → client: 32-byte random nonce
AUTH_RESPONSE       = 0x05   # client → server: RC5‑encrypted "username:password"
AUTH_OK             = 0x06   # server → client: identity accepted
AUTH_FAIL           = 0x07   # server → client: identity rejected → drop
SERVER_CERTIFICATE  = 0x08   # server → client: signed certificate containing public key
MSG_PACKET          = 0x10
FILE_PACKET         = 0x11
AUTH_PACKET         = 0xFF   # reserved — future quantum phase
REGISTER_PACKET     = 0x09

_PACKET_NAMES = {
    CLIENT_HELLO:        "CLIENT_HELLO",
    SERVER_PUBLIC_KEY:   "SERVER_PUBLIC_KEY",
    SESSION_KEY_CT:      "SESSION_KEY_CT",
    SESSION_ESTABLISHED: "SESSION_ESTABLISHED",
    AUTH_CHALLENGE:      "AUTH_CHALLENGE",
    AUTH_RESPONSE:       "AUTH_RESPONSE",
    AUTH_OK:             "AUTH_OK",
    AUTH_FAIL:           "AUTH_FAIL",
    SERVER_CERTIFICATE:  "SERVER_CERTIFICATE",
    MSG_PACKET:          "MSG_PACKET",
    FILE_PACKET:         "FILE_PACKET",
    REGISTER_PACKET:     "REGISTER_PACKET",
    AUTH_PACKET:         "AUTH_PACKET",
}

# ─────────────────────────────────────────────────────────────────────────────
# User credential store – NTRU registration data
# In production this would be a database.  Populated by register_user().
# ─────────────────────────────────────────────────────────────────────────────
_NTRU_STORE: dict = {}   # { username: registration_data }

def load_or_generate_ntru_keys(username: str) -> tuple:
    """Load NTRU keys from disk or generate new ones and save them.

    All key files are stored under NTRU_KEY_DIR (= PROJECT_ROOT) using
    absolute paths so the location is identical regardless of the
    working directory from which the script is launched.
    """
    priv_file = os.path.join(NTRU_KEY_DIR, f"{username}_ntru_priv.json")
    pub_file  = os.path.join(NTRU_KEY_DIR, f"{username}_ntru_pub.json")
    reg_file  = os.path.join(NTRU_KEY_DIR, f"{username}_ntru_reg.json")

    if os.path.exists(priv_file) and os.path.exists(pub_file) and os.path.exists(reg_file):
        with open(priv_file, 'r') as f:
            priv = json.load(f)
        with open(pub_file, 'r') as f:
            pub = json.load(f)
        with open(reg_file, 'r') as f:
            reg = json.load(f)
        print(f"[Auth] Loaded existing NTRU keys for {username!r} from {NTRU_KEY_DIR}")
    else:
        print(f"[Auth] Generating NTRU key pair for {username!r}...")
        priv, pub, reg, _ = generate_ntru_keypair(user_id=username)
        with open(priv_file, 'w') as f:
            json.dump(priv, f)
        with open(pub_file, 'w') as f:
            json.dump(pub, f)
        with open(reg_file, 'w') as f:
            json.dump(reg, f)
        print(f"[Auth] Saved NTRU keys for {username!r} to {NTRU_KEY_DIR}")
    return priv, pub, reg

def register_user(username: str) -> None:
    """Load/Generate NTRU keys and register the public data in the store."""
    _, _, reg = load_or_generate_ntru_keys(username)
    _NTRU_STORE[username] = reg
    print(f"[Auth] Registered NTRU user: {username!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe client registry
#
# clients[cid] = {
#     "socket"          : socket.socket,
#     "session_key"     : bytes | None,
#     "handshake_complete": bool,
#     "username"        : str | None,
#     "auth_complete"   : bool,
#     "seq_send"        : int,
#     "seq_recv"        : int,
# }
# ─────────────────────────────────────────────────────────────────────────────
clients_lock = threading.Lock()
clients: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# Server ElGamal key pair  (persistent, or ephemeral per connection)
# ─────────────────────────────────────────────────────────────────────────────
_server_keypair: Optional[ElGamalKeyPair] = None
_keypair_lock = threading.Lock()
_server_ca: Optional[CertificateAuthority] = None
_branch_trust_monitor: Optional[SilentTrustMonitor] = None
_branch_peer_id: Optional[str] = None   # used by branch console to name the peer


# =============================================================================
#  SERVER KEY INITIALISATION
# =============================================================================

def initialize_server_keys() -> ElGamalKeyPair:
    """
    Generate the server's ElGamal key pair.

    Called ONCE at server startup — BEFORE socket.bind() / socket.listen().
    If USE_EPHEMERAL_KEYPAIR is True this is also called per connection.
    """
    if USE_SMALL_PRIME:
        kp = generate_keypair(_P_SMALL, _G_SMALL)
    else:
        kp = generate_keypair(_P_1024, _G_1024)

    print("=" * 60)
    print("  [ElGamal] Server key pair generated")
    print("=" * 60)
    p_str = str(kp.p)
    print(f"  p  = {p_str[:32]}…  ({kp.p.bit_length()}-bit)")
    print(f"  g  = {kp.g}")
    y_str = str(kp.y)
    print(f"  y  = {y_str[:32]}…  (g^x mod p)")
    print(f"  x  = <HIDDEN>  (private key — never transmitted)")
    print(f"  mode = {'ephemeral (per-connection)' if USE_EPHEMERAL_KEYPAIR else 'persistent (server lifetime)'}")
    print("=" * 60 + "\n")
    return kp


# ─────────────────────────────────────────────────────────────────────────────
# Low-level framed I/O
# ─────────────────────────────────────────────────────────────────────────────

def _recvall(conn: socket.socket, n: int) -> Optional[bytes]:
    """Reliably read exactly n bytes. Returns None if connection closes."""
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_raw(conn: socket.socket, ptype: int, payload: bytes) -> None:
    """Send [1B TYPE][4B BE LENGTH][PAYLOAD]."""
    conn.sendall(struct.pack('>BI', ptype, len(payload)) + payload)


def _recv_raw(conn: socket.socket) -> Optional[tuple]:
    """
    Receive one packet. Returns (ptype, payload) or None on disconnect.
    Raises ValueError on absurdly large declared length (DoS guard).
    """
    header = _recvall(conn, 5)
    if header is None:
        return None
    ptype, length = struct.unpack('>BI', header)

    MAX_PACKET = 64 * 1024 * 1024   # 64 MB ceiling
    if length > MAX_PACKET:
        raise ValueError(
            f"Packet declares {length} B — exceeds {MAX_PACKET // (1024*1024)} MB ceiling."
        )

    payload = _recvall(conn, length)
    if payload is None:
        return None
    return ptype, payload


# ─────────────────────────────────────────────────────────────────────────────
# Anti‑replay: sequence‑number helpers
# ─────────────────────────────────────────────────────────────────────────────

def _wrap_with_seq(content: bytes, seq: int) -> bytes:
    """Prepend a 4-byte big-endian sequence number to content."""
    return struct.pack('>I', seq) + content


def _unwrap_seq(payload: bytes) -> tuple:
    """
    Extract (seq, content) from a sequence-wrapped payload.
    Raises ValueError if payload is too short.
    """
    if len(payload) < 4:
        raise ValueError(f"Payload too short for sequence header: {len(payload)} B.")
    seq = struct.unpack_from('>I', payload, 0)[0]
    content = payload[4:]
    return seq, content


def _check_seq(seq: int, last_seq: int, cid: str) -> bool:
    """
    Return True if seq is strictly greater than last_seq (fresh packet).
    Return False if seq <= last_seq (replay or duplicate — reject).
    """
    if seq <= last_seq:
        print(f"[AntiReplay] {cid}: rejected seq={seq} (last accepted={last_seq}).")
        return False
    return True


def _send_seq(conn: socket.socket, ptype: int,
              content: bytes, cid: str) -> None:
    """Send a sequence-protected packet."""
    with clients_lock:
        entry = clients.get(cid)
        if entry is None:
            return
        seq = entry["seq_send"]
        entry["seq_send"] = seq + 1

    _send_raw(conn, ptype, _wrap_with_seq(content, seq))


def _recv_seq(payload: bytes, cid: str) -> Optional[bytes]:
    """
    Verify and strip the sequence number from an incoming payload.
    Updates seq_recv on success.  Returns inner content or None on replay.
    """
    try:
        seq, content = _unwrap_seq(payload)
    except ValueError as exc:
        print(f"[AntiReplay] {cid}: malformed payload — {exc}")
        return None

    with clients_lock:
        entry = clients.get(cid)
        if entry is None:
            return None
        last_seq = entry["seq_recv"]

    if not _check_seq(seq, last_seq, cid):
        return None

    with clients_lock:
        if cid in clients:
            clients[cid]["seq_recv"] = seq

    return content


# ─────────────────────────────────────────────────────────────────────────────
# Handshake — server side
# ─────────────────────────────────────────────────────────────────────────────

def _server_run_handshake(conn: socket.socket,
                           keypair: ElGamalKeyPair,
                           client_id: str,
                           server_cert: dict) -> Optional[bytes]:
    """
    Server-side ElGamal handshake.

    Protocol:
      0. Wait for CLIENT_HELLO
      1. Send SERVER_CERTIFICATE
      2. Wait for SESSION_KEY_CT
      3. Decrypt → session key bytes
      4. Send SESSION_ESTABLISHED
      5. Return session key
    """
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)

        pkt = _recv_raw(conn)
        if pkt is None:
            _hs_fail(client_id, "Connection closed before CLIENT_HELLO.")
            return None
        ptype, _ = pkt
        if ptype != CLIENT_HELLO:
            _hs_fail(client_id, f"Expected CLIENT_HELLO, got 0x{ptype:02X}.")
            return None
        print(f"  [HS:{client_id}] CLIENT_HELLO received")

        cert_bytes = json.dumps(server_cert).encode('utf-8')
        _send_raw(conn, SERVER_CERTIFICATE, cert_bytes)
        print(f"  [HS:{client_id}] SERVER_CERTIFICATE sent  ({len(cert_bytes)} B)")

        pkt = _recv_raw(conn)
        if pkt is None:
            _hs_fail(client_id, "Connection closed waiting for SESSION_KEY_CT.")
            return None
        ptype, ct_bytes = pkt
        if ptype != SESSION_KEY_CT:
            _hs_fail(client_id, f"Expected SESSION_KEY_CT, got 0x{ptype:02X}.")
            return None

        try:
            a, b = deserialize_ciphertext(ct_bytes, keypair.p)
        except ValueError as exc:
            _hs_fail(client_id, f"Malformed ciphertext — {exc}")
            return None

        try:
            m = elgamal_decrypt(a, b, keypair)
        except Exception as exc:
            _hs_fail(client_id, f"ElGamal decryption failed — {exc}")
            return None

        session_key = int_to_session_key_bytes(m, SESSION_KEY_BYTES)
        print(f"  [HS:{client_id}] Session key recovered  "
              f"(fingerprint: {session_key.hex()[:8]}…)")

        _send_raw(conn, SESSION_ESTABLISHED, b"OK")
        print(f"  [HS:{client_id}] SESSION_ESTABLISHED sent")
        return session_key

    except socket.timeout:
        _hs_fail(client_id, f"Timed out after {HANDSHAKE_TIMEOUT}s.")
        return None
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        _hs_fail(client_id, f"Network error — {exc}")
        return None
    finally:
        conn.settimeout(None)


# ─────────────────────────────────────────────────────────────────────────────
# Authentication – server side (no hashing, RC5‑encrypted credentials)
# ─────────────────────────────────────────────────────────────────────────────

def _server_run_auth(conn: socket.socket, cid: str, session_key: bytes) -> Optional[str]:
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)

        # Step 0: check if client wants to register first
        # Peek at the next packet — if it's REGISTER_PACKET, store the reg data
        conn.settimeout(5.0)
        pkt = _recv_raw(conn)
        conn.settimeout(HANDSHAKE_TIMEOUT)

        if pkt is None:
            print(f"  [Auth:{cid}] Connection closed before registration/challenge.")
            return None

        ptype, payload = pkt

        if ptype == REGISTER_PACKET:
            # Client is sending their public NTRU registration data
            try:
                reg_data = json.loads(payload.decode('utf-8'))
                username = reg_data.get("user_id")
                if not username:
                    raise ValueError("Missing user_id in registration")
            except Exception as exc:
                print(f"  [Auth:{cid}] Bad REGISTER packet: {exc}")
                _send_raw(conn, AUTH_FAIL, b"Bad registration")
                return None

            # Only accept registration if user is unknown OR keys match
            existing = _NTRU_STORE.get(username)
            if existing is None:
                _NTRU_STORE[username] = reg_data
                print(f"  [Auth:{cid}] Registered new user {username!r} from client")
            elif existing.get("h") != reg_data.get("h"):
                # Known user with DIFFERENT public key — reject
                print(f"  [Auth:{cid}] Key mismatch for known user {username!r} — rejected")
                _send_raw(conn, AUTH_FAIL, b"Key mismatch")
                return None
            # else: same keys — already registered, proceed

            # Now send challenge
            temp_auth = NTRUAuthenticator()
            nonce = temp_auth.create_challenge()
            _send_raw(conn, AUTH_CHALLENGE, struct.pack('>I', nonce))
            print(f"  [Auth:{cid}] NTRU Challenge sent (nonce={nonce})")

        elif ptype == AUTH_RESPONSE:
            # Old clients that skip registration — handle as before
            # (shouldn't happen in normal flow but keep backward compat)
            print(f"  [Auth:{cid}] Client skipped registration phase.")
            _send_raw(conn, AUTH_FAIL, b"Registration required")
            return None

        else:
            print(f"  [Auth:{cid}] Expected REGISTER or AUTH_RESPONSE, got 0x{ptype:02X}")
            _send_raw(conn, AUTH_FAIL, b"Protocol error")
            return None

        # Step 2: receive response
        pkt = _recv_raw(conn)
        if pkt is None:
            print(f"  [Auth:{cid}] Connection closed before AUTH_RESPONSE.")
            return None
        ptype, payload = pkt
        if ptype != AUTH_RESPONSE:
            print(f"  [Auth:{cid}] Expected AUTH_RESPONSE, got 0x{ptype:02X}.")
            _send_raw(conn, AUTH_FAIL, b"Protocol error")
            return None

        # Step 3: decode and verify
        try:
            data     = json.loads(payload.decode('utf-8'))
            username = data.get("username")
            response = data.get("response")
        except Exception as exc:
            print(f"  [Auth:{cid}] JSON decode error: {exc}")
            _send_raw(conn, AUTH_FAIL, b"Malformed payload")
            return None

        reg_data = _NTRU_STORE.get(username)
        if reg_data is None:
            print(f"  [Auth:{cid}] Unknown username {username!r}.")
            _send_raw(conn, AUTH_FAIL, b"Authentication failed")
            return None

        authenticator = NTRUAuthenticator(registration_data=reg_data)
        authenticator.current_nonce = nonce
        
        try:
            is_valid = authenticator.check_response(response)
        except Exception as exc:
            print(f"  [Auth:{cid}] NTRU verification exception: {exc}")
            is_valid = False

        if not is_valid:
            print(f"  [Auth:{cid}] NTRU signature verification failed for {username!r}.")
            _send_raw(conn, AUTH_FAIL, b"Authentication failed")
            return None

        _send_raw(conn, AUTH_OK, username.encode('utf-8'))
        print(f"  [Auth:{cid}] Authenticated via NTRU as {username!r}")
        return username

    except socket.timeout:
        print(f"  [Auth:{cid}] Auth timed out.")
        return None
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        print(f"  [Auth:{cid}] Network error — {exc}")
        return None
    finally:
        conn.settimeout(None)


# ─────────────────────────────────────────────────────────────────────────────
# Handshake — client side
# ─────────────────────────────────────────────────────────────────────────────

def _client_run_handshake(conn: socket.socket) -> Optional[bytes]:
    """
    Client-side ElGamal handshake.
    """
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)

        _send_raw(conn, CLIENT_HELLO, b"HELLO")
        print("  [HS] CLIENT_HELLO sent")

        pkt = _recv_raw(conn)
        if pkt is None:
            print("  [HS] Connection closed before SERVER_CERTIFICATE.")
            return None
        ptype, cert_bytes = pkt
        if ptype != SERVER_CERTIFICATE:
            print(f"  [HS] Expected SERVER_CERTIFICATE, got 0x{ptype:02X}.")
            return None

        try:
            cert_dict = json.loads(cert_bytes.decode('utf-8'))
        except Exception as exc:
            print(f"  [HS] Invalid certificate format — {exc}")
            return None

        if not verify_certificate(cert_dict, CA_PUBLIC_KEY):
            print("  [HS] ABORT: Server certificate verification failed! Invalid signature or issuer.")
            return None
            
        print("  [HS] SERVER_CERTIFICATE verified successfully using CA Public Key.")

        try:
            pub = cert_dict["data"]["public_key"]
            _validate_public_key(pub)
        except Exception as exc:
            print(f"  [HS] Invalid server public key in certificate — {exc}")
            return None

        p = pub["p"]
        print(f"  [HS] SERVER_PUBLIC_KEY validated  ({p.bit_length()}-bit prime)")

        session_key = generate_session_key_bytes()
        m = session_key_bytes_to_int(session_key)

        if not (1 <= m < p):
            print(
                "  [HS] ABORT: session key integer out of ElGamal range. "
                "Ensure USE_SMALL_PRIME=False and SESSION_KEY_BYTES=32."
            )
            return None

        try:
            a, b = elgamal_encrypt(m, pub)
        except ValueError as exc:
            print(f"  [HS] Encryption failed — {exc}")
            return None

        ct_bytes = serialize_ciphertext(a, b, p)
        _send_raw(conn, SESSION_KEY_CT, ct_bytes)
        print(f"  [HS] SESSION_KEY_CT sent  ({len(ct_bytes)} B)")

        pkt = _recv_raw(conn)
        if pkt is None:
            print("  [HS] Connection closed before SESSION_ESTABLISHED.")
            return None
        ptype, _ = pkt
        if ptype != SESSION_ESTABLISHED:
            print(f"  [HS] Expected SESSION_ESTABLISHED, got 0x{ptype:02X}.")
            return None
        print("  [HS] SESSION_ESTABLISHED received")

        final_key = int_to_session_key_bytes(m, SESSION_KEY_BYTES)
        return final_key

    except socket.timeout:
        print(f"  [HS] Timed out after {HANDSHAKE_TIMEOUT}s.")
        return None
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        print(f"  [HS] Network error — {exc}")
        return None
    finally:
        conn.settimeout(None)


# ─────────────────────────────────────────────────────────────────────────────
# Authentication – client side (no hashing, RC5‑encrypted credentials)
# ─────────────────────────────────────────────────────────────────────────────

def _client_run_auth(conn: socket.socket,
                     username: str, priv_key: dict, pub_key: dict, reg_data: dict,
                     session_key: bytes) -> bool:
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)

        # Step 0: send our public registration data so server can verify us
        # reg data = dict which contains user_id, h, and vk
        _send_raw(conn, REGISTER_PACKET, json.dumps(reg_data).encode('utf-8'))
        print(f"  [Auth] Registration data sent for {username!r}")

        # Step 1: receive challenge
        pkt = _recv_raw(conn)
        if pkt is None:
            print("  [Auth] Connection closed before AUTH_CHALLENGE.")
            return False
        ptype, payload = pkt

        if ptype == AUTH_FAIL:
            print("  [Auth] Server rejected registration.")
            return False
        if ptype != AUTH_CHALLENGE:
            print(f"  [Auth] Expected AUTH_CHALLENGE, got 0x{ptype:02X}.")
            return False

        try:
            nonce = struct.unpack('>I', payload)[0]
        except Exception as exc:
            print(f"  [Auth] Malformed challenge payload: {exc}")
            return False

        print(f"  [Auth] NTRU Challenge received (nonce={nonce})")

        # Step 2: sign and respond
        authenticator = NTRUAuthenticator(private_key=priv_key, public_key=pub_key)
        response_poly = authenticator.respond_to_challenge(nonce)
        auth_data = {"username": username, "response": response_poly}
        _send_raw(conn, AUTH_RESPONSE, json.dumps(auth_data).encode('utf-8'))
        print("  [Auth] NTRU signature sent")

        # Step 3: result
        pkt = _recv_raw(conn)
        if pkt is None:
            print("  [Auth] Connection closed waiting for result.")
            return False
        ptype, _ = pkt
        if ptype == AUTH_OK:
            print(f"  [Auth] Authenticated via NTRU as {username!r}")
            return True
        print("  [Auth] Server rejected signature.")
        return False

    except socket.timeout:
        print("  [Auth] Timed out.")
        return False
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        print(f"  [Auth] Network error — {exc}")
        return False
    finally:
        conn.settimeout(None)


def _hs_fail(client_id: str, reason: str) -> None:
    print(f"  [HS:{client_id}] FAILED — {reason}")


# ─────────────────────────────────────────────────────────────────────────────
# RC5 message helpers
# ─────────────────────────────────────────────────────────────────────────────

def _send_message(conn: socket.socket, msg: str,
                  key: bytes, cid: str) -> None:
    encrypted = encrypt_message(msg, key)
    _send_seq(conn, MSG_PACKET, encrypted, cid)


def _recv_message(payload: bytes, key: bytes,
                  cid: str) -> Optional[str]:
    content = _recv_seq(payload, cid)
    if content is None:
        return None
    try:
        return decrypt_message(content, key)
    except Exception as exc:
        print(f"[RC5] Decryption error from {cid}: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Feistel file helpers
# ─────────────────────────────────────────────────────────────────────────────

def _send_file(conn: socket.socket, filepath: str,
               key: bytes, cid: str) -> None:
    fname = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    if len(plaintext) > MAX_FILE_BYTES:
        raise ValueError(f"File '{fname}' is {len(plaintext)} B — exceeds 1 MB limit.")

    ciphertext  = feistel_encrypt_bytes(plaintext, key)
    fname_bytes = fname.encode('utf-8')
    content = (
        struct.pack('>H', len(fname_bytes)) + fname_bytes +
        struct.pack('>I', len(plaintext))   + ciphertext
    )
    _send_seq(conn, FILE_PACKET, content, cid)


def _recv_file(payload: bytes, key: bytes,
               cid: str, save_dir: str = "received") -> Optional[str]:
    content = _recv_seq(payload, cid)
    if content is None:
        return None

    try:
        offset = 0
        if len(content) < 6:
            raise ValueError(f"FILE content too short: {len(content)} B.")

        fname_len = struct.unpack_from('>H', content, offset)[0]; offset += 2
        if fname_len == 0 or fname_len > 255:
            raise ValueError(f"Invalid filename length: {fname_len}.")
        if offset + fname_len + 4 > len(content):
            raise ValueError("FILE content truncated.")

        fname     = content[offset:offset + fname_len].decode('utf-8', errors='replace')
        offset   += fname_len
        orig_size = struct.unpack_from('>I', content, offset)[0]; offset += 4

        if orig_size > MAX_FILE_BYTES:
            raise ValueError(f"Declared size {orig_size} B > 1 MB.")

        ciphertext = content[offset:]
        plaintext  = feistel_decrypt_bytes(ciphertext, key)

        if len(plaintext) != orig_size:
            raise ValueError(f"Size mismatch: declared {orig_size} B, got {len(plaintext)} B.")

        os.makedirs(save_dir, exist_ok=True)
        safe_name = os.path.basename(fname)
        save_path = os.path.join(save_dir, safe_name)
        if os.path.exists(save_path):
            base, ext = os.path.splitext(safe_name)
            i = 1
            while os.path.exists(save_path):
                save_path = os.path.join(save_dir, f"{base}_{i}{ext}")
                i += 1

        with open(save_path, 'wb') as fh:
            fh.write(plaintext)
        return save_path

    except Exception as exc:
        print(f"[Feistel] File receive error from {cid}: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Server — broadcast helpers
# ─────────────────────────────────────────────────────────────────────────────

def _broadcast_message(msg: str, sender_id: str) -> None:
    with clients_lock:
        targets = [
            (cid, entry["socket"], entry["session_key"])
            for cid, entry in clients.items()
            if cid != sender_id
            and entry["handshake_complete"]
            and entry.get("auth_complete", False)
            and entry["session_key"]
        ]

    dead = []
    for cid, sock, key in targets:
        try:
            encrypted = encrypt_message(msg, key)
            with clients_lock:
                if cid not in clients:
                    continue
                seq = clients[cid]["seq_send"]
                clients[cid]["seq_send"] = seq + 1
            _send_raw(sock, MSG_PACKET, _wrap_with_seq(encrypted, seq))
        except (BrokenPipeError, ConnectionResetError, OSError):
            dead.append(cid)

    _purge_dead(dead)


def _broadcast_file(plaintext: bytes, fname: str, sender_id: str) -> None:
    fname_bytes = fname.encode('utf-8')

    with clients_lock:
        targets = [
            (rcid, entry["socket"], entry["session_key"])
            for rcid, entry in clients.items()
            if rcid != sender_id
            and entry["handshake_complete"]
            and entry.get("auth_complete", False)
            and entry["session_key"] is not None
        ]

    dead = []
    for rcid, sock, recv_key in targets:
        try:
            ct = feistel_encrypt_bytes(plaintext, recv_key)
            file_content = (
                struct.pack('>H', len(fname_bytes)) + fname_bytes +
                struct.pack('>I', len(plaintext))   + ct
            )
            with clients_lock:
                if rcid not in clients:
                    continue
                seq = clients[rcid]["seq_send"]
                clients[rcid]["seq_send"] = seq + 1
            _send_raw(sock, FILE_PACKET, _wrap_with_seq(file_content, seq))
        except (BrokenPipeError, ConnectionResetError, OSError):
            dead.append(rcid)
        except Exception as exc:
            print(f"[Server] File re-encrypt error for {rcid}: {exc}")

    _purge_dead(dead)


def _broadcast_raw(ptype: int, payload: bytes, sender_id: str) -> None:
    with clients_lock:
        targets = [
            (cid, entry["socket"])
            for cid, entry in clients.items()
            if cid != sender_id
            and entry["handshake_complete"]
            and entry.get("auth_complete", False)
        ]

    dead = []
    for cid, sock in targets:
        try:
            _send_raw(sock, ptype, payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            dead.append(cid)

    _purge_dead(dead)


def _purge_dead(dead: list) -> None:
    if dead:
        with clients_lock:
            for cid in dead:
                clients.pop(cid, None)
        for cid in dead:
            print(f"[Server] Purged dead client: {cid}")


# ─────────────────────────────────────────────────────────────────────────────
# Server — per-client thread
# ─────────────────────────────────────────────────────────────────────────────
import ipaddress
import random

def ping(host):
    """Mock ping returning a simulated latency."""
    return random.uniform(10.0, 100.0)

def choose_branch(client_ip):
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return "Branch_A"
        
    latency_a = ping("10.0.0.1")  # Branch A
    latency_b = ping("10.0.1.1")  # Branch B

    return "Branch_A" if latency_a < latency_b else "Branch_B"

def _handle_client(conn: socket.socket, addr: tuple) -> None:
    cid = f"{addr[0]}:{addr[1]}"
    print(f"\n[Server] New connection: {cid}")
    
    client_ip = addr[0]
    branch = choose_branch(client_ip)
    print(f"[Router] Client IP: {client_ip} → Assigned to {branch}")

    try:
        conn.settimeout(5.0)
        pkt = _recv_raw(conn)
        if pkt and pkt[0] == 0x99:
            company_name = pkt[1].decode('utf-8', errors='replace')
            print(f"[Server] Company: {company_name}")
        conn.settimeout(None)
    except Exception:
        pass

    # 1. Key pair
    if USE_EPHEMERAL_KEYPAIR:
        print(f"  [Server] Generating ephemeral ElGamal key pair for {cid} …")
        keypair = initialize_server_keys()
    else:
        with _keypair_lock:
            keypair = _server_keypair

    # 2. Handshake
    print(f"  [Server] Starting handshake with {cid} …")
    cert = _server_ca.issue_certificate("SERVER", keypair.public_key)
    session_key = _server_run_handshake(conn, keypair, cid, cert)
    if session_key is None:
        print(f"  [Server] Handshake failed — dropping {cid}.")
        conn.close()
        with clients_lock:
            clients.pop(cid, None)
        return

    with clients_lock:
        if cid in clients:
            clients[cid]["session_key"]        = session_key
            clients[cid]["handshake_complete"] = True

    print(f"  [Server] Secure channel with {cid}  "
          f"(fingerprint: {session_key.hex()[:8]}…)")

    # 3. Authentication
    username = _server_run_auth(conn, cid, session_key)
    if username is None:
        print(f"  [Server] Authentication failed — dropping {cid}.")
        conn.close()
        with clients_lock:
            clients.pop(cid, None)
        return

    with clients_lock:
        if cid in clients:
            clients[cid]["username"]      = username
            clients[cid]["auth_complete"] = True

    print(f"  [Server] {username!r} authenticated from {cid}")
    print(f"  [Server] Total authenticated clients: "
          f"{sum(1 for e in clients.values() if e.get('auth_complete'))}")

    # 4. Welcome
    try:
        _send_message(
            conn,
            f"[Server] Welcome {username}!  "
            f"Key fingerprint: {session_key.hex()[:8]}…",
            key=session_key, cid=cid
        )
    except Exception:
        pass

    _broadcast_message(
        f"[Server] {username} joined.  "
        f"Online: {sum(1 for e in clients.values() if e.get('auth_complete'))}",
        sender_id=cid
    )

    # 5. Receive loop
    os.makedirs("received", exist_ok=True)
    try:
        while True:
            pkt = _recv_raw(conn)
            if pkt is None:
                print(f"\n[Server] {username}@{cid} disconnected.")
                break

            ptype, payload = pkt

            with clients_lock:
                fully_ready = (
                    clients.get(cid, {}).get("handshake_complete", False)
                    and clients.get(cid, {}).get("auth_complete", False)
                )
            if not fully_ready and ptype in (MSG_PACKET, FILE_PACKET):
                pname = _PACKET_NAMES.get(ptype, f'0x{ptype:02X}')
                print(f"[Security] BLOCKED {pname} from {cid} "
                      f"— not authenticated (pre-auth attack detected).")
                continue

            if ptype == MSG_PACKET:
                plain = _recv_message(payload, key=session_key, cid=cid)
                if plain is None:
                    continue
                if plain == "__QUIT__":
                    print(f"[Server] {username} quit.")
                    _broadcast_message(f"[{username} has left]", sender_id=cid)
                    break
                print(f"\r[{username}]: {plain}")
                print("You (broadcast): ", end='', flush=True)
                _broadcast_message(f"[{username}]: {plain}", sender_id=cid)

            elif ptype == FILE_PACKET:
                saved = _recv_file(payload, key=session_key,
                                   cid=cid, save_dir="received")
                if saved:
                    with open(saved, 'rb') as fh:
                        file_plaintext = fh.read()
                    size = len(file_plaintext)
                    fname = os.path.basename(saved)
                    print(f"\r[Server] File from {username}: {fname} ({size} B)")
                    print("You (broadcast): ", end='', flush=True)
                    _broadcast_message(
                        f"[Server] {username} sent '{fname}' ({size} B)",
                        sender_id=cid
                    )
                    _broadcast_file(file_plaintext, fname, sender_id=cid)
                else:
                    print(f"[Server] File from {username}@{cid} failed decryption.")

            else:
                name = _PACKET_NAMES.get(ptype, f"0x{ptype:02X}")
                print(f"[Server] Unknown packet {name} from {cid} — ignored.")

    except ValueError as exc:
        print(f"[Server] Protocol error from {cid}: {exc} — dropping.")
    except (ConnectionResetError, BrokenPipeError, OSError):
        print(f"\n[Server] Connection lost: {cid}")
    finally:
        with clients_lock:
            clients.pop(cid, None)
        conn.close()
        remaining = sum(1 for e in clients.values() if e.get("auth_complete"))
        print(f"[Server] Authenticated clients remaining: {remaining}")


def _server_console_loop(
        trust_monitor: Optional[SilentTrustMonitor] = None,
        peer_branch_id: Optional[str] = None
) -> None:
    is_branch = trust_monitor is not None
    label = "[Branch]" if is_branch else "[Server]"

    print("\nServer console ready.")
    print("  <message>       → broadcast to all authenticated clients")
    print("  /file <path>    → broadcast encrypted file (re-encrypted per client)")
    print("  /info           → show connection info (LAN/WAN IP, port)")
    print("  /tunnel         → open ngrok tunnel (clients on ANY network can connect)")
    if is_branch:
        print("  /trust          → show Silent Trust status for peer branch")
    print("  quit            → stop console\n")

    while True:
        try:
            raw = input("You (broadcast): ").strip()
        except EOFError:
            break

        if not raw:
            continue
        if raw.lower() == 'quit':
            break

        # ── /info — display connection info ──────────────────────────────────
        if raw.lower() == '/info':
            print("\n" + "─" * 50)
            print("  Connection Info")
            print("─" * 50)
            if _server_lan_ip:
                print(f"  LAN     →  {_server_lan_ip}:{_server_port}")
            if _server_public_ip and _server_public_ip != "<unavailable>":
                print(f"  WAN     →  {_server_public_ip}:{_server_port}")
            else:
                print(f"  WAN     →  <unavailable> (port {_server_port}/TCP)")
            if _tunnel_url:
                print(f"  TUNNEL  →  {_tunnel_url}")
            else:
                print(f"  TUNNEL  →  inactive (type /tunnel to start)")
            online = sum(1 for e in clients.values() if e.get('auth_complete'))
            print(f"  Online clients: {online}")
            print("─" * 50 + "\n")
            continue

        # ── /tunnel — start ngrok tunnel ──────────────────────────────────────
        if raw.lower() == '/tunnel':
            if _tunnel_url:
                print(f"[Tunnel] Already active: {_tunnel_url}")
            else:
                _start_tunnel(_server_port)
            continue

        # ── /trust — branch-only command ─────────────────────────────────────
        if raw.lower() == '/trust':
            if not is_branch:
                print("[Server] /trust is only available in branch-server mode.")
                continue
            status = trust_monitor.status()
            print("\n" + "─" * 50)
            print("  Silent Trust Status")
            print("─" * 50)
            for pid, info in status.items():
                age = time.time() - info["last_seen"]
                age_str = f"{age:.0f}s ago" if info["last_seen"] > 0 else "never"
                print(f"  {pid:<20}  {info['state']:<12}  misses={info['misses']}  last_seen={age_str}")
            print("─" * 50 + "\n")
            continue

        # ── /file — broadcast with trust gate in branch mode ─────────────────
        if raw.startswith('/file '):
            filepath = raw[6:].strip()
            if not os.path.isfile(filepath):
                print(f"{label} Not found: {filepath}")
                continue

            # Silent Trust gate — branch mode only
            # Check ALL discovered peers — allow if at least one is TRUSTED
            if is_branch:
                status = trust_monitor.status()
                if not status:
                    print(
                        "[Branch] FILE BLOCKED — no peer branches discovered yet.\n"
                        "[Branch] Waiting for automatic discovery…\n"
                        "[Branch] Use /trust to inspect current state."
                    )
                    continue
                any_trusted = any(
                    info["state"] == "TRUSTED" for info in status.values()
                )
                if not any_trusted:
                    blocked_list = ", ".join(
                        f"{pid}={info['state']}" for pid, info in status.items()
                    )
                    print(
                        f"[Branch] FILE BLOCKED — no peer is TRUSTED.\n"
                        f"[Branch] Peer states: {blocked_list}\n"
                        f"[Branch] Use /trust to inspect current state."
                    )
                    continue

            with open(filepath, 'rb') as fh:
                plaintext = fh.read()
            if len(plaintext) > MAX_FILE_BYTES:
                print(f"{label} File too large (>{MAX_FILE_BYTES} B).")
                continue

            fname = os.path.basename(filepath)
            _broadcast_message(
                f"{label} Broadcasting file: {fname} ({len(plaintext)} B)",
                sender_id="__server__"
            )
            _broadcast_file(plaintext, fname, sender_id="__server__")
            print(f"{label} File '{fname}' sent to all authenticated clients.")
        else:
            _broadcast_message(f"{label}: {raw}", sender_id="__server__")


def start_server() -> None:
    global _server_keypair, _server_ca

    _server_ca = CertificateAuthority()

    with _keypair_lock:
        _server_keypair = initialize_server_keys()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((HOST, PORT))
        except OSError as exc:
            in_use = exc.errno == errno.EADDRINUSE or exc.errno == 10048  # WSAEADDRINUSE
            if in_use:
                script = os.path.abspath(__file__)
                print(
                    f"[Server] Port {PORT} is already in use.\n"
                    f"[Server] Stop the other listener, or use a free port, for example:\n"
                    f"         CHAT_PORT=5001 python3 {script}",
                    file=sys.stderr,
                )
                sys.exit(1)
            raise
        srv.listen(10)

        print(f"[Server] Listening on {HOST}:{PORT}")
        print(f"[Server] Handshake timeout: {HANDSHAKE_TIMEOUT}s")
        print(f"[Server] Key mode: {'ephemeral' if USE_EPHEMERAL_KEYPAIR else 'persistent'}")
        print("[Server] ElGamal handshake + NTRU post-quantum authentication active")
        print("[Server] Anti-replay sequence numbers active")
        print("[Server] Per-client file re-encryption active\n")

        _display_connection_info(PORT, label="Server")

        threading.Thread(target=_server_console_loop, daemon=True).start()  # client-mode: no trust_monitor

        while True:
            try:
                conn, addr = srv.accept()
                cid = f"{addr[0]}:{addr[1]}"
                with clients_lock:
                    clients[cid] = {
                        "socket"            : conn,
                        "session_key"       : None,
                        "handshake_complete": False,
                        "username"          : None,
                        "auth_complete"     : False,
                        "seq_send"          : 1,
                        "seq_recv"          : 0,
                    }
                threading.Thread(
                    target=_handle_client, args=(conn, addr), daemon=True
                ).start()

            except KeyboardInterrupt:
                print("\n[Server] Interrupted.")
                break
            except OSError as exc:
                print(f"[Server] Accept error: {exc}")
                break


# ─────────────────────────────────────────────────────────────────────────────
# Branch auto-discovery helpers
# ─────────────────────────────────────────────────────────────────────────────

# These ports are automatically derived from the main CHAT_PORT — no config needed.
_HB_PORT        = PORT + 500    # heartbeat channel   (5000→5500, 5001→5501, …)
# Discovery port is FIXED across all branches so they can find each other.
# If Branch A uses CHAT_PORT=5000 and Branch B uses CHAT_PORT=5001,
# both must broadcast/listen on the SAME UDP port for discovery.
_DISC_PORT      = 6000          # shared UDP discovery port for ALL branches
_DISC_INTERVAL  = 3             # broadcast every N seconds (was 5, faster discovery)


def _get_local_ip() -> str:
    """Return this machine's primary LAN IP (not loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _disc_broadcaster(branch_id: str, own_cert: dict,
                       own_ip: str, stop_evt: threading.Event) -> None:
    """UDP broadcast: announce this branch to the LAN every _DISC_INTERVAL seconds."""
    payload = json.dumps({
        "type":      "BRANCH_HELLO",
        "branch_id": branch_id,
        "ip":        own_ip,
        "hb_port":   _HB_PORT,
        "cert":      own_cert,
    }).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    while not stop_evt.is_set():
        # Send to LAN broadcast + own LAN IP (not 127.0.0.1).
        # Using own_ip ensures that when two branches run on the same
        # machine, the packet goes through the real network stack so both
        # SO_REUSEPORT listeners can receive it.
        for dest in ("255.255.255.255", own_ip):
            try:
                sock.sendto(payload, (dest, _DISC_PORT))
            except OSError:
                pass
        stop_evt.wait(_DISC_INTERVAL)

    sock.close()


def _disc_listener(branch_id: str,
                    trust_monitor: SilentTrustMonitor,
                    stop_evt: threading.Event) -> None:
    """Listen for UDP BRANCH_HELLO packets and auto-register new peers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # SO_REUSEPORT lets multiple branches on the same machine share port 6000
    if hasattr(socket, 'SO_REUSEPORT'):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind(("", _DISC_PORT))
    except OSError as exc:
        print(f"[Discovery] Cannot bind port {_DISC_PORT}: {exc}")
        return

    sock.settimeout(1.0)
    seen: set = set()    # already-processed peer IDs

    while not stop_evt.is_set():
        try:
            data, (src_ip, _) = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            pkt       = json.loads(data.decode())
            peer_id   = pkt["branch_id"]
            peer_ip   = pkt.get("ip", src_ip)
            peer_hb   = int(pkt["hb_port"])
            peer_cert = pkt["cert"]
        except (KeyError, ValueError, json.JSONDecodeError):
            continue

        if pkt.get("type") != "BRANCH_HELLO":
            continue
        if peer_id == branch_id:          # ignore our own broadcasts
            continue
        if peer_id in seen:               # already registered
            continue

        # Verify the cert was signed by the CA
        if not verify_certificate(peer_cert, CA_PUBLIC_KEY):
            print(f"\n[Discovery] Peer {peer_id!r} cert FAILED CA verification — ignored.")
            continue

        # Cert subject must match the declared branch_id
        if peer_cert.get("data", {}).get("subject") != peer_id:
            print(f"\n[Discovery] Cert subject mismatch from {peer_id!r} — ignored.")
            continue

        seen.add(peer_id)
        trust_monitor.add_peer(peer_id, peer_cert, peer_ip, peer_hb)
        print(
            f"\n[Discovery] ✓ Peer {peer_id!r} found at {peer_ip}"
            f"\n[Discovery]   Cert verified — Silent Trust monitoring started"
            f"\n[Discovery]   Waiting for first heartbeat to reach TRUSTED…\n"
            f"You (broadcast): ", end="", flush=True
        )

    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Branch Server — plug-and-play, zero manual configuration
# ─────────────────────────────────────────────────────────────────────────────

def start_branch_server() -> None:
    """
    Branch-to-branch secure server with automatic peer discovery.

    The user only types a branch name (or presses Enter for the hostname).
    Everything else — IP detection, peer discovery, cert exchange,
    Silent Trust activation — happens automatically.
    """
    global _server_keypair, _server_ca, _branch_trust_monitor, _branch_peer_id

    # ── ONLY prompt: branch name ──────────────────────────────────────────────
    default_name = socket.gethostname()
    branch_id = input(f"Branch name [{default_name}]: ").strip() or default_name

    # ── Auto-detect own LAN IP ────────────────────────────────────────────────
    own_ip = _get_local_ip()

    # ── CA + ElGamal keypair ──────────────────────────────────────────────────
    _server_ca = CertificateAuthority()
    with _keypair_lock:
        _server_keypair = initialize_server_keys()

    # ── Issue own CA-signed certificate ──────────────────────────────────────
    own_cert      = _server_ca.issue_certificate(branch_id, _server_keypair.public_key)
    own_cert_file = f"{branch_id}_cert.json"
    with open(own_cert_file, 'w') as f:
        json.dump(own_cert, f, indent=2)

    # ── Start Silent Trust Monitor (empty peer list — discovery fills it) ─────
    _branch_peer_id       = branch_id   # updated when first peer is found
    _branch_trust_monitor = SilentTrustMonitor(
        branch_id=branch_id,
        keypair=_server_keypair,
        peer_certs={},          # starts empty; add_peer() populates at runtime
        hb_port=_HB_PORT,
    )
    _branch_trust_monitor.start()   # no peer_addresses — discovery provides them

    # ── Start auto-discovery threads ──────────────────────────────────────────
    _stop_disc = threading.Event()
    threading.Thread(
        target=_disc_broadcaster,
        args=(branch_id, own_cert, own_ip, _stop_disc),
        daemon=True
    ).start()
    threading.Thread(
        target=_disc_listener,
        args=(branch_id, _branch_trust_monitor, _stop_disc),
        daemon=True
    ).start()

    # ── Banner ────────────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print(f"  [Branch Mode]  {branch_id}  —  {own_ip}")
    print(f"  Chat port      {PORT}   (clients connect here)")
    print(f"  Heartbeat port {_HB_PORT}  (automatic, branch-to-branch)")
    print(f"  Discovery      broadcasting on LAN every {_DISC_INTERVAL}s…")
    print("─" * 60)
    print("  Peers discovered automatically — no manual IP entry needed")
    print("  File transfers blocked until peer reaches TRUSTED state")
    print("═" * 60 + "\n")

    _display_connection_info(PORT, label="Branch")

    # ── Socket accept loop ────────────────────────────────────────────────────
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((HOST, PORT))
        except OSError as exc:
            _stop_disc.set()
            in_use = exc.errno == errno.EADDRINUSE or exc.errno == 10048
            if in_use:
                script = os.path.abspath(__file__)
                print(
                    f"[Branch] Port {PORT} is already in use.\n"
                    f"[Branch] For local testing run second branch with:\n"
                    f"         CHAT_PORT={PORT+1} python3 {script}",
                    file=sys.stderr,
                )
                return
            raise
        srv.listen(10)

        print(f"[Branch] Listening on {HOST}:{PORT}")
        print("[Branch] ElGamal + NTRU auth + Silent Trust active\n")

        threading.Thread(
            target=_server_console_loop,
            kwargs=dict(
                trust_monitor=_branch_trust_monitor,
                peer_branch_id=_branch_peer_id,
            ),
            daemon=True
        ).start()

        while True:
            try:
                conn, addr = srv.accept()
                cid = f"{addr[0]}:{addr[1]}"
                with clients_lock:
                    clients[cid] = {
                        "socket"            : conn,
                        "session_key"       : None,
                        "handshake_complete": False,
                        "username"          : None,
                        "auth_complete"     : False,
                        "seq_send"          : 1,
                        "seq_recv"          : 0,
                    }
                threading.Thread(
                    target=_handle_client, args=(conn, addr), daemon=True
                ).start()

            except KeyboardInterrupt:
                print("\n[Branch] Interrupted.")
                break
            except OSError as exc:
                print(f"[Branch] Accept error: {exc}")
                break


_client_seq_lock = threading.Lock()
_client_seq_send = [1]
_client_seq_recv = [0]

# Attack Simulation — packet capture store
# Populated by the client send loop after every successful MSG send.
# The /replay attack re-transmits this verbatim so the server's anti-replay
# check fires (same sequence number → rejected).
_ATTACK_LAST_RAW_PACKET: Optional[bytes] = None   # full wire payload (seq-wrapped ciphertext)
_ATTACK_LAST_RAW_PTYPE:  int             = MSG_PACKET
_ATTACK_RAW_LOCK         = threading.Lock()


def _client_send_seq(conn: socket.socket, ptype: int,
                     content: bytes) -> None:
    with _client_seq_lock:
        seq = _client_seq_send[0]
        _client_seq_send[0] = seq + 1
    _send_raw(conn, ptype, _wrap_with_seq(content, seq))


def _client_recv_seq(payload: bytes, label: str = "server") -> Optional[bytes]:
    try:
        seq, content = _unwrap_seq(payload)
    except ValueError as exc:
        print(f"\n[AntiReplay] {exc}")
        return None
    with _client_seq_lock:
        last = _client_seq_recv[0]
    if not _check_seq(seq, last, label):
        return None
    with _client_seq_lock:
        _client_seq_recv[0] = seq
    return content


def _client_recv_loop(conn: socket.socket, session_key: bytes) -> None:
    os.makedirs("received", exist_ok=True)
    while True:
        try:
            pkt = _recv_raw(conn)
            if pkt is None:
                print("\n[Disconnected from server]")
                break
            ptype, payload = pkt

            if ptype == MSG_PACKET:
                content = _client_recv_seq(payload)
                if content is None:
                    continue
                try:
                    plain = decrypt_message(content, session_key)
                except Exception as exc:
                    print(f"\n[RC5] Decrypt error: {exc}")
                    continue
                if plain == "__QUIT__":
                    print("\n[Server closed the connection]")
                    break
                print(f"\r{plain}\nYou: ", end='', flush=True)

            elif ptype == FILE_PACKET:
                print("\r[Receiving file …]")
                content = _client_recv_seq(payload)
                if content is None:
                    print("[File] Replay detected — discarded.")
                    print("You: ", end='', flush=True)
                    continue
                try:
                    offset    = 0
                    fname_len = struct.unpack_from('>H', content, offset)[0]; offset += 2
                    fname     = content[offset:offset + fname_len].decode('utf-8', errors='replace')
                    offset   += fname_len
                    orig_size = struct.unpack_from('>I', content, offset)[0]; offset += 4
                    ciphertext = content[offset:]
                    plaintext  = feistel_decrypt_bytes(ciphertext, session_key)
                    if len(plaintext) != orig_size:
                        raise ValueError(f"Size mismatch: {orig_size} vs {len(plaintext)}")
                    save_dir  = "received"
                    safe_name = os.path.basename(fname)
                    save_path = os.path.join(save_dir, safe_name)
                    if os.path.exists(save_path):
                        base, ext = os.path.splitext(safe_name)
                        i = 1
                        while os.path.exists(save_path):
                            save_path = os.path.join(save_dir, f"{base}_{i}{ext}")
                            i += 1
                    with open(save_path, 'wb') as fh:
                        fh.write(plaintext)
                    print(f"[File] Saved → {save_path}  ({orig_size} B)")
                except Exception as exc:
                    print(f"[File] Decrypt/save error: {exc}")
                print("You: ", end='', flush=True)

            else:
                name = _PACKET_NAMES.get(ptype, f"0x{ptype:02X}")
                print(f"\r[Unexpected packet: {name}]\nYou: ", end='', flush=True)

        except ValueError as exc:
            print(f"\n[Protocol error: {exc}]")
            break
        except (ConnectionResetError, BrokenPipeError, OSError):
            print("\n[Connection lost]")
            break
        except Exception as exc:
            print(f"\n[Error: {exc}]")
            break


# ─────────────────────────────────────────────────────────────────────────────
# Attack Simulation — dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def _attack_run(conn: socket.socket, session_key: bytes,
                mode: str, cid: str) -> None:
    """
    Simulate one of five network-layer attacks against the live server.

    All attacks are intentionally visible in the SERVER terminal so the
    reviewer can confirm the defences fire correctly.

    Modes
    -----
    replay   – Re-sends the last captured MSG_PACKET verbatim (identical
               sequence number) → server anti-replay rejects it.
    fake     – Sends two packets with invalid ptypes (0x99, 0xDE).
               → server logs "Unknown packet … ignored" for each.
    preauth  – Opens a fresh raw TCP connection, skips the full handshake
               and auth, then immediately sends a MSG_PACKET.
               → server logs "BLOCKED … not authenticated".
    fuzz     – Sends 5 MSG_PACKETs with random-length random-byte payloads.
               → server tries to unwrap seq header, fails gracefully.
    spam     – Sends 20 properly encrypted messages in rapid succession.
               → server stays stable; tests stress/stability.
    """
    import random as _rng

    _W   = "\033[38;2;239;159;39m"   # orange
    _ERR = "\033[38;2;226;75;74m"    # red
    _OK  = "\033[38;2;93;202;165m"   # green
    _RST = "\033[0m"

    def _hdr(title: str) -> None:
        print(f"\n  {_W}◆ ATTACK: {title}{_RST}")
        print(f"  {'─' * 56}")

    # ── help ──────────────────────────────────────────────────────────────────
    if mode in ('', 'help'):
        print()
        print(f"  {_W}Available /attack modes:{_RST}")
        print("    replay   → replay last MSG packet (triggers anti-replay)")
        print("    fake     → send invalid packet types (0x99, 0xDE)")
        print("    preauth  → send MSG before auth on a fresh connection")
        print("    fuzz     → send 5 random malformed payloads")
        print("    spam     → flood 20 messages rapidly (stress test)")
        print()
        return

    # ── replay ────────────────────────────────────────────────────────────────
    if mode == 'replay':
        _hdr("REPLAY ATTACK")
        with _ATTACK_RAW_LOCK:
            ptype   = _ATTACK_LAST_RAW_PTYPE
            payload = _ATTACK_LAST_RAW_PACKET
        if payload is None:
            print(f"  {_ERR}✗  No packet captured yet — send a message first.{_RST}")
            return
        print(f"  Resending last MSG_PACKET verbatim ({len(payload)} B) …")
        try:
            _send_raw(conn, ptype, payload)   # same seq → server rejects
            print(f"  {_OK}✔  Replay packet sent — check server for [AntiReplay] rejection.{_RST}")
        except OSError as exc:
            print(f"  {_ERR}✗  Send error: {exc}{_RST}")
        return

    # ── fake ──────────────────────────────────────────────────────────────────
    if mode == 'fake':
        _hdr("FAKE / INVALID PACKET TYPE")
        for ptype_val in (0x99, 0xDE):
            junk = b"FAKE_PACKET_" + bytes([ptype_val] * 8)
            try:
                _send_raw(conn, ptype_val, junk)
                print(f"  Sent invalid ptype=0x{ptype_val:02X}  ({len(junk)} B)")
            except OSError as exc:
                print(f"  {_ERR}✗  Could not send 0x{ptype_val:02X}: {exc}{_RST}")
                break
        print(f"  {_OK}✔  Check server for [Server] Unknown packet … ignored.{_RST}")
        return

    # ── preauth ───────────────────────────────────────────────────────────────
    if mode == 'preauth':
        _hdr("PRE-AUTH ATTACK (unauthenticated MSG)")
        try:
            peer_host, peer_port = conn.getpeername()
        except OSError:
            print(f"  {_ERR}✗  Cannot read peer address from socket.{_RST}")
            return
        raw_conn = None
        try:
            raw_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_conn.settimeout(5.0)
            raw_conn.connect((peer_host, peer_port))
            print(f"  Raw connection opened to {peer_host}:{peer_port}")
            # Send MSG_PACKET WITHOUT any handshake or authentication
            junk_payload = _wrap_with_seq(b"PREAUTH_ATTACK", 1)
            _send_raw(raw_conn, MSG_PACKET, junk_payload)
            print("  Sent MSG_PACKET without any handshake or authentication")
            print(f"  {_OK}✔  Check server for [Security] BLOCKED MSG_PACKET.{_RST}")
        except OSError as exc:
            print(f"  {_ERR}✗  Connection error: {exc}{_RST}")
        finally:
            if raw_conn is not None:
                try:
                    raw_conn.close()
                except Exception:
                    pass
        return

    # ── fuzz ──────────────────────────────────────────────────────────────────
    if mode == 'fuzz':
        _hdr("INPUT FUZZING (random malformed payloads)")
        for i in range(5):
            size    = _rng.randint(0, 512)
            garbage = bytes(_rng.getrandbits(8) for _ in range(size))
            try:
                _send_raw(conn, MSG_PACKET, garbage)
                print(f"  Fuzz #{i+1}: sent {size} random bytes as MSG_PACKET")
            except OSError as exc:
                print(f"  {_ERR}✗  Fuzz #{i+1}: send error — {exc}{_RST}")
                break
        print(f"  {_OK}✔  Check server is still running (no crash).{_RST}")
        return

    # ── spam ──────────────────────────────────────────────────────────────────
    if mode == 'spam':
        _hdr("SPAM / STRESS TEST (20 rapid messages)")
        ok = 0
        for i in range(20):
            try:
                msg       = f"[SPAM {i+1}/20] stress-test message"
                encrypted = encrypt_message(msg, session_key)
                _send_seq(conn, MSG_PACKET, encrypted, cid)
                ok += 1
            except OSError as exc:
                print(f"  {_ERR}✗  Spam #{i+1}: {exc}{_RST}")
                break
        print(f"  {_OK}✔  Sent {ok}/20 spam messages — verify server stayed stable.{_RST}")
        return

    # ── unknown mode ──────────────────────────────────────────────────────────
    print(f"  {_ERR}✗  Unknown attack mode: {mode!r}{_RST}")
    print("     Type /attack help for available modes.")


# ─────────────────────────────────────────────────────────────────────────────
# Client — entry point
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    # greens  (teal palette — matches Shegha brand)
    G1      = "\033[38;2;29;158;117m"    # #1D9E75  accent
    G2      = "\033[38;2;93;202;165m"    # #5DCAA5  bright
    G3      = "\033[38;2;159;225;203m"   # #9FE1CB  highlight
    G4      = "\033[38;2;8;80;65m"       # #085041  dark bg label
    # neutrals
    W       = "\033[38;2;250;249;245m"   # warm white
    MUT     = "\033[38;2;180;178;169m"   # muted
    # status
    OK      = "\033[38;2;93;202;165m"
    WARN    = "\033[38;2;239;159;39m"
    ERR     = "\033[38;2;226;75;74m"
    INFO    = "\033[38;2;55;138;221m"

def _line(char="─", width=62, color=C.G4):
    print(f"{color}{char * width}{C.RESET}")

def print_banner():
    """Print the Shegha ASCII banner with colours."""
    print()
    logo_lines = [
        r"   _____ _               _           ",
        r"  / ____| |             | |          ",
        r" | (___ | |__   ___  __ _| |__   __ _ ",
        r"  \___ \| '_ \ / _ \/ _` | '_ \ / _` |",
        r"  ____) | | | |  __/ (_| | | | | (_| |",
        r" |_____/|_| |_|\___|\__, |_| |_|\__,_|",
        r"                     __/ |            ",
        r"                    |___/             ",
    ]
    for line in logo_lines:
        print(f"{C.G1}{C.BOLD}{line}{C.RESET}")

    print(f"  {C.G2}Hybrid Cryptography · Post-Quantum Auth · ElGamal{C.RESET}")
    _line()
    print(f"  {C.MUT}don't look back{C.RESET}")
    print()


def _tag(label, text, color=C.G3):
    """Print a formatted [TAG] line."""
    print(f"  {C.G4}[{C.RESET}{color}{label}{C.RESET}{C.G4}]{C.RESET}  {C.W}{text}{C.RESET}")


def _status(symbol, label, detail="", color=C.OK):
    """Print a status line: ✔  LABEL  detail"""
    print(f"  {color}{symbol}{C.RESET}  {C.BOLD}{C.W}{label}{C.RESET}  {C.MUT}{detail}{C.RESET}")


def _spinner(message, duration=0.6, color=C.G1):
    """Simple terminal spinner for short async moments."""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.time() + duration
    i = 0
    while time.time() < end:
        frame = frames[i % len(frames)]
        print(f"\r  {color}{frame}{C.RESET}  {C.MUT}{message}{C.RESET}", end="", flush=True)
        time.sleep(0.07)
        i += 1
    print(f"\r  {C.OK}✔{C.RESET}  {C.MUT}{message}{C.RESET}            ")


def _section(title):
    """Print a section divider with a title."""
    print()
    print(f"  {C.G1}◆{C.RESET}  {C.BOLD}{C.W}{title}{C.RESET}")
    _line("·", 62, C.G4)

def start_client() -> None:
    server_input = input("Enter domain name (or IP): ").strip()
    if not server_input:
        print("[Client] Domain name required.")
        sys.exit(1)

    # ── DNS resolution with validation ────────────────────────────────────
    try:
        resolved_ip, hostname, is_domain = _resolve_domain(server_input)
    except ValueError as exc:
        print(f"[Client] {exc}")
        sys.exit(1)

    if is_domain:
        _section("DNS Resolution")
        _status("✔", "RESOLVED", f"{hostname} → {resolved_ip}")
    else:
        _section("Target")
        _status("✔", "IP", resolved_ip)

    # ── Port configuration ────────────────────────────────────────────────
    port_input = input(f"Server port [{PORT}]: ").strip()
    if port_input:
        try:
            server_port = int(port_input)
            if not (1 <= server_port <= 65535):
                raise ValueError("out of range")
        except ValueError:
            print(f"[Client] Invalid port — using default {PORT}")
            server_port = PORT
    else:
        server_port = PORT

    company_name = input("Company name: ").strip()
    if not company_name:
        print("[Client] Company name required.")
        sys.exit(1)

    username = input("Username: ").strip()
    if not username:
        print("[Client] Username required.")
        sys.exit(1)

    priv_key, pub_key, reg_data = load_or_generate_ntru_keys(username)

    with _client_seq_lock:
        _client_seq_send[0] = 1
        _client_seq_recv[0] = 0

    # ── Connection with automatic retry ───────────────────────────────────
    s = None
    for attempt in range(1, _MAX_CONNECT_RETRIES + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.settimeout(_CONNECT_TIMEOUT)
            tag = f"(attempt {attempt}/{_MAX_CONNECT_RETRIES})" if _MAX_CONNECT_RETRIES > 1 else ""
            print(f"[Client] Connecting to {hostname}:{server_port} … {tag}")
            s.connect((resolved_ip, server_port))
            s.settimeout(None)
            print("[Client] TCP connection established.")
            break
        except ConnectionRefusedError:
            s.close(); s = None
            if attempt < _MAX_CONNECT_RETRIES:
                print(f"[Client] Refused — retrying in {_RETRY_DELAY}s …")
                time.sleep(_RETRY_DELAY)
            else:
                print(f"[Client] Refused — is the server running on {hostname}:{server_port}?")
                sys.exit(1)
        except (TimeoutError, socket.timeout):
            s.close(); s = None
            if attempt < _MAX_CONNECT_RETRIES:
                print(f"[Client] Timed out — retrying in {_RETRY_DELAY}s …")
                time.sleep(_RETRY_DELAY)
            else:
                print(f"[Client] Timed out after {_MAX_CONNECT_RETRIES} attempts.")
                sys.exit(1)
        except OSError as exc:
            if s: s.close()
            print(f"[Client] Connection error: {exc}")
            sys.exit(1)

    if s is None:
        print("[Client] Failed to connect.")
        sys.exit(1)

    _send_raw(s, 0x99, company_name.encode())

    print("\n[Client] Starting ElGamal handshake …")
    session_key = _client_run_handshake(s)
    if session_key is None:
        print("[Client] Handshake failed. Exiting.")
        s.close()
        sys.exit(1)
    print(f"[Client] Secure channel active  "
          f"(fingerprint: {session_key.hex()[:8]}…)")

    print("[Client] Authenticating via NTRU …")
    if not _client_run_auth(s, username, priv_key, pub_key, reg_data, session_key):
        print("[Client] Authentication failed. Exiting.")
        s.close()
        sys.exit(1)
    print(f"[Client] Authenticated as {username!r}\n")

    threading.Thread(
        target=_client_recv_loop, args=(s, session_key), daemon=True
    ).start()

    _W   = "\033[38;2;239;159;39m"
    _G   = "\033[38;2;93;202;165m"
    _MUT = "\033[38;2;180;178;169m"
    _RST = "\033[0m"
    print()
    print(f"  {_G}{'═' * 56}{_RST}")
    print(f"  {_G}Hybrid Encrypted Chat — session active{_RST}")
    print(f"  {'─' * 56}")
    print(f"  {_MUT}<message>          → RC5-encrypted text (anti-replay seq){_RST}")
    print(f"  {_MUT}/file <path>       → Feistel-encrypted file transfer{_RST}")
    print(f"  {_MUT}quit               → disconnect gracefully{_RST}")
    print(f"  {'─' * 56}")
    print(f"  {_W}Attack Simulation (for demo/testing):{_RST}")
    print(f"  {_MUT}/attack replay     → replay last packet  (anti-replay fires){_RST}")
    print(f"  {_MUT}/attack fake       → send invalid ptypes (0x99, 0xDE){_RST}")
    print(f"  {_MUT}/attack preauth    → MSG before auth     (pre-auth block fires){_RST}")
    print(f"  {_MUT}/attack fuzz       → 5 random malformed payloads (fuzz test){_RST}")
    print(f"  {_MUT}/attack spam       → 20 rapid messages   (stress / stability){_RST}")
    print(f"  {_G}{'═' * 56}{_RST}")
    print()

    _CLIENT_CID = "__client__"
    with clients_lock:
        clients[_CLIENT_CID] = {
            "socket": s, "session_key": session_key,
            "handshake_complete": True, "auth_complete": True,
            "username": username,
            "seq_send": 1, "seq_recv": 0,
        }

    try:
        while True:
            try:
                raw = input("You: ").strip()
            except EOFError:
                break

            if raw.lower() == 'quit':
                try:
                    encrypted = encrypt_message("__QUIT__", session_key)
                    _send_seq(s, MSG_PACKET, encrypted, _CLIENT_CID)
                except Exception:
                    pass
                break

            if not raw:
                continue

            if raw.startswith('/file '):
                filepath = raw[6:].strip()
                if not os.path.isfile(filepath):
                    print(f"[Client] File not found: {filepath}")
                    continue
                fsize = os.path.getsize(filepath)
                if fsize > MAX_FILE_BYTES:
                    print(f"[Client] File too large: {fsize} B (limit 1 MB).")
                    continue
                try:
                    print(f"[Client] Feistel-encrypting "
                          f"{os.path.basename(filepath)} ({fsize} B) …")
                    _send_file(s, filepath, key=session_key, cid=_CLIENT_CID)
                    encrypted_notif = encrypt_message(
                        f"[File sent: {os.path.basename(filepath)}, {fsize} B]",
                        session_key
                    )
                    _send_seq(s, MSG_PACKET, encrypted_notif, _CLIENT_CID)
                    print("[Client] File sent successfully.")
                except (BrokenPipeError, ConnectionResetError):
                    print("[Client] Connection lost during file send.")
                    break
                except Exception as exc:
                    print(f"[Client] File error: {exc}")

            elif raw.startswith('/attack'):
                mode = raw[7:].strip().lower()
                _attack_run(s, session_key, mode, _CLIENT_CID)

            else:
                try:
                    encrypted = encrypt_message(raw, session_key)
                    with _client_seq_lock:
                        seq = _client_seq_send[0]
                    _send_seq(s, MSG_PACKET, encrypted, _CLIENT_CID)
                    # Capture the full wire payload for /attack replay
                    with _ATTACK_RAW_LOCK:
                        global _ATTACK_LAST_RAW_PACKET, _ATTACK_LAST_RAW_PTYPE
                        _ATTACK_LAST_RAW_PACKET = _wrap_with_seq(encrypted, seq)
                        _ATTACK_LAST_RAW_PTYPE  = MSG_PACKET
                except (BrokenPipeError, ConnectionResetError):
                    print("[Client] Connection lost.")
                    break

    except KeyboardInterrupt:
        print("\n[Interrupted]")
    finally:
        with clients_lock:
            clients.pop(_CLIENT_CID, None)
        s.close()
        print("[Client] Disconnected.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("═" * 60)
    print("  Shegha Hybrid Encrypted Secure Chat")
    print("─" * 60)
    print("  server        → company server  (NTRU auth, client chat)")
    print("  branch-server → branch node     (NTRU + Silent Trust)")
    print("  client        → connect as user")
    print("═" * 60)
    role = input("Start as (server / branch-server / client): ").strip().lower()
    # accept common variations
    role = role.replace(' ', '-')
    if role == 'server':
        start_server()
    elif role in ('branch-server', 'branch', 'bs'):
        start_branch_server()
    elif role == 'client':
        start_client()
    else:
        print("Please type 'server', 'branch-server', or 'client'.")
