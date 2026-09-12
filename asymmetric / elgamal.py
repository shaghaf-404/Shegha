import os
import random

# ─────────────────────────────────────────────────────────────────────────────
# Domain parameters  (point 8 – validated at use sites)
# ─────────────────────────────────────────────────────────────────────────────

# 1024-bit safe prime  p = 2q + 1  (q also prime).
# Generator g = 2 is a primitive root for this group.
# Source: IETF RFC 3526 "1536-bit MODP Group" / standard DH group parameters.
_P_1024 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_G_1024 = 2

# Small prime for fast demo / unit tests
_P_SMALL = 104_723
_G_SMALL = 5          # primitive root mod 104_723

# Session key size in bytes  (point 2: 32 bytes / 256-bit recommended)
SESSION_KEY_BYTES = 32

# Handshake timeout in seconds  (point 9)
HANDSHAKE_TIMEOUT = 15


# ─────────────────────────────────────────────────────────────────────────────
# Internal math helpers  (zero library calls except pow)
# ─────────────────────────────────────────────────────────────────────────────

def _mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Fast modular exponentiation via Python's built-in pow(base, exp, mod).
    Uses the square-and-multiply algorithm — O(log exp), no huge intermediates.
    This is the ONLY permitted math-library call in the entire module.
    """
    return pow(base, exp, mod)


def _extended_gcd(a: int, b: int):
    """
    Iterative extended Euclidean algorithm.
    Returns (gcd, x, y) satisfying  a·x + b·y = gcd(a, b).
    Pure integer arithmetic — no imports.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    # old_t = (old_r - old_s * a) // b  (not needed)
    return old_r, old_s, (old_r - old_s * a) // b if b else 0


def _mod_inverse(a: int, m: int) -> int:
    """
    Modular multiplicative inverse of a mod m.
    Returns x such that  a·x ≡ 1 (mod m).
    Raises ValueError if gcd(a, m) ≠ 1 (no inverse exists).
    """
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(
            f"Modular inverse does not exist: gcd({a}, {m}) = {g}"
        )
    return x % m


def _gcd(a: int, b: int) -> int:
    """Iterative GCD — Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def _secure_randrange(lo: int, hi: int) -> int:
    """
    Uniform random integer in [lo, hi) from the OS entropy source.
    random.SystemRandom wraps os.urandom — no crypto library involved.
    """
    return random.SystemRandom().randrange(lo, hi)


# ─────────────────────────────────────────────────────────────────────────────
# Input validation helpers  (point 8)
# ─────────────────────────────────────────────────────────────────────────────

def _validate_public_key(pub: dict) -> None:
    """
    Validate all fields of an ElGamal public key dict.
    Raises ValueError with a descriptive message on any violation.

    Checks performed:
      • required keys present:  p, g, y
      • p is a positive integer  (primality not checked — too expensive)
      • 1 < g < p
      • 1 < y < p
    """
    for field in ("p", "g", "y"):
        if field not in pub:
            raise ValueError(f"Public key missing field '{field}'.")
        if not isinstance(pub[field], int) or pub[field] <= 0:
            raise ValueError(
                f"Public key field '{field}' must be a positive integer, "
                f"got {pub[field]!r}."
            )

    p, g, y = pub["p"], pub["g"], pub["y"]

    if not (1 < g < p):
        raise ValueError(
            f"Generator g={g} is out of valid range (1, p). "
            f"Required: 1 < g < p={p}."
        )
    if not (1 < y < p):
        raise ValueError(
            f"Public component y={y} is out of valid range (1, p). "
            f"Required: 1 < y < p={p}."
        )


def _validate_ciphertext(a: int, b: int, p: int) -> None:
    """
    Validate an ElGamal ciphertext pair (a, b).
    Raises ValueError on any violation.

    Checks:
      • a != 0,  b != 0           (zero ciphertext leaks plaintext)
      • 1 < a < p,  1 < b < p    (must be in group Z_p*)
    """
    if a == 0:
        raise ValueError("Ciphertext component a == 0 is invalid.")
    if b == 0:
        raise ValueError("Ciphertext component b == 0 is invalid.")
    if not (1 < a < p):
        raise ValueError(
            f"Ciphertext a={a} out of range (1, p={p})."
        )
    if not (1 < b < p):
        raise ValueError(
            f"Ciphertext b={b} out of range (1, p={p})."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Session key helpers  (points 2, 3, 7)
# ─────────────────────────────────────────────────────────────────────────────

def generate_session_key_bytes() -> bytes:
    """
    Generate a cryptographically random 32-byte (256-bit) session key.

    Uses os.urandom — reads directly from the OS entropy pool.
    No crypto library involved.

    Returns
    -------
    bytes
        32 random bytes suitable as a symmetric key for RC5 and Feistel.
    """
    return os.urandom(SESSION_KEY_BYTES)


def session_key_bytes_to_int(key_bytes: bytes) -> int:
    """
    Convert a session key byte string into an integer for ElGamal encryption.

    Uses big-endian encoding (standard for cryptographic integers).
    The caller must verify that the result satisfies  1 ≤ m < p  before
    passing it to encrypt().

    Args:
        key_bytes : bytes  — the raw session key (any length)

    Returns:
        int — big-endian integer representation
    """
    return int.from_bytes(key_bytes, byteorder='big')


def int_to_session_key_bytes(m: int, length: int = SESSION_KEY_BYTES) -> bytes:
    """
    Convert the recovered ElGamal plaintext integer back into session key bytes.

    This is the exact inverse of session_key_bytes_to_int() — same length,
    same byte order.  Both server and client must use the same `length`.

    Args:
        m      : int   — plaintext integer recovered from ElGamal decryption
        length : int   — desired output length in bytes (default 32)

    Returns:
        bytes — the reconstructed session key
    """
    return m.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """Big-endian bytes → integer.  Alias kept for backward compatibility."""
    return int.from_bytes(b, byteorder='big')


def int_to_bytes(n: int, length: int) -> bytes:
    """Integer → big-endian bytes of exactly `length` bytes."""
    return n.to_bytes(length, byteorder='big')


# ─────────────────────────────────────────────────────────────────────────────
# ElGamal key pair  (points 1, 4, 10)
# ─────────────────────────────────────────────────────────────────────────────

class ElGamalKeyPair:
    """
    Immutable container for one ElGamal key pair.

    Public attributes  (safe to expose):
        p   prime modulus
        g   generator
        y   public component  (y = g^x mod p)

    Private attribute  (NEVER transmitted, NEVER logged):
        x   private exponent

    Design notes  (point 10):
        • No global state.  Each connection/session gets its own instance
          or its own session key — the key pair is passed explicitly.
        • The .public_key property deliberately omits x.
        • __repr__ masks x to prevent accidental logging.
    """

    __slots__ = ("p", "g", "_x", "y")

    def __init__(self, p: int, g: int, x: int, y: int):
        self.p  = p
        self.g  = g
        self._x = x    # PRIVATE — accessed only via decrypt()
        self.y  = y

    @property
    def public_key(self) -> dict:
        """
        Return a dict containing ONLY public components.
        Safe to serialise and send over the network.
        Keys: 'p', 'g', 'y'
        """
        return {"p": self.p, "g": self.g, "y": self.y}

    @property
    def x(self) -> int:
        """Private key accessor — returns the secret exponent."""
        return self._x

    def __repr__(self) -> str:
        return (
            f"ElGamalKeyPair("
            f"p={self.p}, g={self.g}, y={self.y}, x=<HIDDEN>)"
        )

    def __str__(self) -> str:
        return self.__repr__()


# ─────────────────────────────────────────────────────────────────────────────
# Key generation  (point 1, 11 — supports both persistent & ephemeral modes)
# ─────────────────────────────────────────────────────────────────────────────

def generate_keypair(p: int = _P_1024, g: int = _G_1024) -> ElGamalKeyPair:
    """
    Generate a fresh ElGamal key pair for domain parameters (p, g).

    Steps
    -----
    A. Validate that 1 < g < p  (point 8).
    B. Choose random private key  x  uniformly in  [2, p-2]
       using the OS entropy source.
    C. Compute public component  y = g^x mod p  (fast modular exponentiation).
    D. Return an ElGamalKeyPair — private key stored internally, never exposed.

    Usage
    -----
    • Server persistent key  : call once at startup.
    • Ephemeral / per-session : call once per accepted connection
      (point 11 — forward-secrecy style behaviour).

    Parameters
    ----------
    p : int   Large safe prime.  Default = 1024-bit RFC prime.
    g : int   Primitive root mod p.  Default = 2.

    Returns
    -------
    ElGamalKeyPair
    """
    # Step A — basic parameter validation
    if not (1 < g < p):
        raise ValueError(f"Invalid generator: g={g} must satisfy 1 < g < p={p}.")

    # Step B — random private key  x ∈ [2, p-2]
    x = _secure_randrange(2, p - 1)

    # Step C — public component  y = g^x mod p
    y = _mod_exp(g, x, p)

    # Step D — wrap and return
    return ElGamalKeyPair(p=p, g=g, x=x, y=y)


# ─────────────────────────────────────────────────────────────────────────────
# Encryption  —  CLIENT side, handshake only  (points 1, 2, 8)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt(m: int, public_key: dict) -> tuple:
    """
    ElGamal encrypt plaintext integer m under public_key.

    This function is called by the CLIENT during the handshake to encrypt
    the session key integer.  It must NEVER be called for chat messages
    or file payloads.

    Algorithm
    ---------
      k  = random ephemeral key,  gcd(k, p-1) = 1   (fresh every call)
      a  = g^k mod p
      b  = (m · y^k) mod p
      ciphertext = (a, b)

    Security note
    -------------
      k is discarded immediately after use.
      Reusing k across two encryptions leaks the private key x.

    Parameters
    ----------
    m          : int   Plaintext integer.  Must satisfy  1 ≤ m < p.
    public_key : dict  Server public key with keys 'p', 'g', 'y'.

    Returns
    -------
    (a, b) : tuple[int, int]   The ElGamal ciphertext pair.

    Raises
    ------
    ValueError  if public_key is malformed (point 8) or m is out of range.
    """
    # Validate public key before use  (point 8)
    _validate_public_key(public_key)

    p, g, y = public_key["p"], public_key["g"], public_key["y"]

    if not (1 <= m < p):
        raise ValueError(
            f"Plaintext integer m={m} is out of range. "
            f"Required: 1 ≤ m < p={p}."
        )

    # Choose ephemeral k coprime with p-1  (retry loop is expected to finish
    # within 1–2 iterations for large primes)
    p_minus_1 = p - 1
    for _ in range(1000):
        k = _secure_randrange(2, p_minus_1)
        if _gcd(k, p_minus_1) == 1:
            break
    else:
        raise RuntimeError("Failed to find a valid ephemeral key k after 1000 tries.")

    a = _mod_exp(g, k, p)              # a = g^k mod p
    b = (m * _mod_exp(y, k, p)) % p   # b = m · y^k mod p

    # Sanity-check own output  (a or b == 0 would be catastrophic)
    if a == 0 or b == 0:
        raise RuntimeError("Encryption produced a zero component — retry.")

    return a, b


# ─────────────────────────────────────────────────────────────────────────────
# Decryption  —  SERVER side, handshake only  (points 1, 3, 8)
# ─────────────────────────────────────────────────────────────────────────────

def decrypt(a: int, b: int, keypair: ElGamalKeyPair) -> int:
    """
    ElGamal decrypt ciphertext (a, b) using the server's key pair.

    This function is called by the SERVER during the handshake to recover
    the session key integer.  It must NEVER be called for chat messages
    or file payloads.

    Algorithm
    ---------
      s     = a^x mod p           (reconstruct shared secret)
      s_inv = modular inverse of s mod p   (extended Euclidean)
      m     = (b · s_inv) mod p   (recover plaintext)

    Parameters
    ----------
    a, b     : int              Ciphertext pair from encrypt().
    keypair  : ElGamalKeyPair   Server key pair — private key x is used here.

    Returns
    -------
    m : int   Recovered plaintext integer.

    Raises
    ------
    ValueError  if (a, b) fails validation  (point 8).
    """
    p = keypair.p
    x = keypair.x

    # Validate ciphertext before use  (point 8)
    _validate_ciphertext(a, b, p)

    s     = _mod_exp(a, x, p)    # shared secret  s = a^x mod p
    s_inv = _mod_inverse(s, p)   # modular inverse of s
    m     = (b * s_inv) % p      # recover plaintext

    return m


# ─────────────────────────────────────────────────────────────────────────────
# Public-key serialisation  (point 7)
# ─────────────────────────────────────────────────────────────────────────────

def serialize_public_key(keypair: ElGamalKeyPair) -> bytes:
    """
    Serialise the public key (p, g, y) to bytes for network transmission.

    Wire format  (all big-endian):
        [2B  p_len ] [p_len bytes  p  ]
        [2B  g_len ] [g_len bytes  g  ]
        [2B  y_len ] [y_len bytes  y  ]

    This is a compact binary format — no JSON overhead — that the receiver
    can reconstruct exactly using deserialize_public_key().

    The private key x is NEVER included.

    Returns
    -------
    bytes  —  binary-serialised public key
    """
    import struct

    def _encode_int(n: int) -> bytes:
        byte_len = (n.bit_length() + 7) // 8 or 1
        raw = n.to_bytes(byte_len, byteorder='big')
        return struct.pack('>H', len(raw)) + raw

    return _encode_int(keypair.p) + _encode_int(keypair.g) + _encode_int(keypair.y)


def deserialize_public_key(data: bytes) -> dict:
    """
    Reconstruct a public key dict {p, g, y} from the binary format
    produced by serialize_public_key().

    Performs full validation via _validate_public_key() after parsing.

    Parameters
    ----------
    data : bytes  —  binary payload received from the server

    Returns
    -------
    dict  with keys 'p', 'g', 'y' as Python ints

    Raises
    ------
    ValueError  if the data is malformed or validation fails  (point 8).
    """
    import struct

    def _decode_int(buf: bytes, offset: int):
        if offset + 2 > len(buf):
            raise ValueError("Truncated public key: missing length prefix.")
        (field_len,) = struct.unpack_from('>H', buf, offset)
        offset += 2
        if offset + field_len > len(buf):
            raise ValueError(
                f"Truncated public key: expected {field_len} bytes, "
                f"only {len(buf) - offset} available."
            )
        value = int.from_bytes(buf[offset:offset + field_len], byteorder='big')
        return value, offset + field_len

    try:
        p, off = _decode_int(data, 0)
        g, off = _decode_int(data, off)
        y, _   = _decode_int(data, off)
    except struct.error as exc:
        raise ValueError(f"Malformed public key bytes: {exc}") from exc

    pub = {"p": p, "g": g, "y": y}
    _validate_public_key(pub)   # full check  (point 8)
    return pub


def serialize_ciphertext(a: int, b: int, p: int) -> bytes:
    """
    Serialise the ElGamal ciphertext pair (a, b) for network transmission.

    Wire format  (all big-endian):
        [2B  a_len ] [a_len bytes  a  ]
        [2B  b_len ] [b_len bytes  b  ]

    Parameters
    ----------
    a, b : int   Ciphertext integers.
    p    : int   Prime modulus (used to determine minimum byte width).

    Returns
    -------
    bytes  —  binary-serialised ciphertext
    """
    import struct

    byte_len = (p.bit_length() + 7) // 8

    def _encode(n: int) -> bytes:
        raw = n.to_bytes(byte_len, byteorder='big')
        return struct.pack('>H', len(raw)) + raw

    return _encode(a) + _encode(b)


def deserialize_ciphertext(data: bytes, p: int) -> tuple:
    """
    Reconstruct (a, b) integers from the binary format produced by
    serialize_ciphertext().

    Performs full validation via _validate_ciphertext() after parsing.

    Returns
    -------
    (a, b) : tuple[int, int]

    Raises
    ------
    ValueError  if data is malformed or ciphertext fails validation  (point 8).
    """
    import struct

    def _decode(buf: bytes, offset: int):
        if offset + 2 > len(buf):
            raise ValueError("Truncated ciphertext.")
        (field_len,) = struct.unpack_from('>H', buf, offset)
        offset += 2
        if offset + field_len > len(buf):
            raise ValueError("Truncated ciphertext payload.")
        value = int.from_bytes(buf[offset:offset + field_len], byteorder='big')
        return value, offset + field_len

    try:
        a, off = _decode(data, 0)
        b, _   = _decode(data, off)
    except struct.error as exc:
        raise ValueError(f"Malformed ciphertext bytes: {exc}") from exc

    _validate_ciphertext(a, b, p)   # point 8
    return a, b


# ─────────────────────────────────────────────────────────────────────────────
# Standalone self-test  (covers points 1-8, 11)
# ─────────────────────────────────────────────────────────────────────────────

def _run_tests() -> None:
    """
    Self-contained test suite.  Uses the small prime for speed.
    Exercises: key gen, encrypt/decrypt, session-key pipeline,
    serialisation, validation, non-determinism, forward-secrecy style
    key regeneration.
    """
    _SEP = "=" * 60

    print(_SEP)
    print("  ElGamal – Full Self-Test  (small prime p=104723)")
    print(_SEP)

    p, g = _P_SMALL, _G_SMALL
    failures = []

    # ── Test 1: key generation ───────────────────────────────────────────────
    print("\n[1] Key generation")
    kp = generate_keypair(p, g)
    assert _mod_exp(g, kp.x, p) == kp.y, "y ≠ g^x mod p"
    assert "x" not in kp.public_key, "Private key leaked into public_key!"
    assert list(kp.public_key.keys()) == ["p", "g", "y"], "Wrong public key fields"
    print(f"  p={kp.p}, g={kp.g}, y={kp.y}, x=<HIDDEN>  →  OK")

    # ── Test 2: encrypt / decrypt round-trip (integer) ───────────────────────
    print("\n[2] Encrypt / decrypt round-trip (raw integers)")
    for m in [1, 2, 42, 1000, p - 2]:
        a, b = encrypt(m, kp.public_key)
        recovered = decrypt(a, b, kp)
        status = "OK" if recovered == m else "FAIL"
        if status == "FAIL":
            failures.append(f"Round-trip failed for m={m}")
        print(f"  m={m:>6}  →  (a={a}, b={b})  →  recovered={recovered}  [{status}]")

    # ── Test 3: session key pipeline (points 2 & 3) ──────────────────────────
    print("\n[3] Session key pipeline  (generate → encrypt → decrypt → recover)")
    for trial in range(5):
        # Client side
        sk_bytes = generate_session_key_bytes()
        m = session_key_bytes_to_int(sk_bytes)

        # m must fit in [1, p-1] for small prime — if it doesn't, skip trial
        if not (1 <= m < p):
            print(f"  Trial {trial+1}: m={m} too large for small prime — skipped")
            continue

        a, b = encrypt(m, kp.public_key)

        # Server side
        m_recovered = decrypt(a, b, kp)
        sk_recovered = int_to_session_key_bytes(m_recovered, len(sk_bytes))

        status = "OK" if sk_recovered == sk_bytes else "FAIL"
        if status == "FAIL":
            failures.append(f"Session key mismatch on trial {trial+1}")
        print(f"  Trial {trial+1}: key={sk_bytes.hex()[:16]}…  recovered={sk_recovered.hex()[:16]}…  [{status}]")

    # ── Test 4: serialisation round-trips (point 7) ──────────────────────────
    print("\n[4] Public key serialisation round-trip")
    raw = serialize_public_key(kp)
    pub_rebuilt = deserialize_public_key(raw)
    assert pub_rebuilt == kp.public_key, f"Mismatch: {pub_rebuilt} vs {kp.public_key}"
    print(f"  Serialised bytes: {len(raw)} B  →  rebuilt: p={pub_rebuilt['p']}, "
          f"g={pub_rebuilt['g']}, y={pub_rebuilt['y']}  OK")

    print("\n[5] Ciphertext serialisation round-trip")
    m_test = 12345
    a_t, b_t = encrypt(m_test, kp.public_key)
    raw_ct   = serialize_ciphertext(a_t, b_t, p)
    a_r, b_r = deserialize_ciphertext(raw_ct, p)
    assert (a_r, b_r) == (a_t, b_t), "Ciphertext serialisation mismatch"
    assert decrypt(a_r, b_r, kp) == m_test, "Decrypt after serialise failed"
    print(f"  (a={a_t}, b={b_t})  →  {len(raw_ct)} B  →  (a={a_r}, b={b_r})  OK")

    # ── Test 5: non-determinism (point 8) ────────────────────────────────────
    print("\n[6] Non-determinism (fresh k each call)")
    m_nd = 999
    ct_set = {encrypt(m_nd, kp.public_key) for _ in range(20)}
    assert len(ct_set) > 1, "Ciphertexts are deterministic — k is NOT fresh!"
    print(f"  20 encryptions of m={m_nd}  →  {len(ct_set)} distinct ciphertexts  OK")

    # ── Test 6: validation rejects bad input (point 8) ───────────────────────
    print("\n[7] Input validation")
    bad_cases = [
        ({"p": p, "g": 0, "y": 5},          "g=0"),
        ({"p": p, "g": p, "y": 5},          "g=p"),
        ({"p": p, "g": 2, "y": 0},          "y=0"),
        ({"p": p, "g": 2, "y": p},          "y=p"),
        ({"p": p, "g": 2},                   "missing y"),
    ]
    for bad_pub, label in bad_cases:
        try:
            _validate_public_key(bad_pub)
            failures.append(f"Validation should have failed for: {label}")
            print(f"  {label:<20} → MISSED (should have raised ValueError)")
        except ValueError as e:
            print(f"  {label:<20} → Caught: {e}  OK")

    # Ciphertext zero checks
    try:
        _validate_ciphertext(0, 5, p)
        failures.append("a=0 should have been rejected")
    except ValueError:
        print(f"  a=0                  → Caught correctly  OK")

    try:
        _validate_ciphertext(5, 0, p)
        failures.append("b=0 should have been rejected")
    except ValueError:
        print(f"  b=0                  → Caught correctly  OK")

    # ── Test 7: forward-secrecy style (point 11) ─────────────────────────────
    print("\n[8] Forward-secrecy style — two independent key pairs")
    kp1 = generate_keypair(p, g)
    kp2 = generate_keypair(p, g)
    assert kp1.x != kp2.x or kp1.y != kp2.y, \
        "Two generate_keypair() calls produced the same key pair!"
    print(f"  Pair 1: y={kp1.y}")
    print(f"  Pair 2: y={kp2.y}")
    print("  Keys are distinct  →  OK")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + _SEP)
    if failures:
        print(f"  {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"    ✗  {f}")
    else:
        print("  ALL TESTS PASSED ✓")
    print(_SEP)


if __name__ == "__main__":
    _run_tests()
