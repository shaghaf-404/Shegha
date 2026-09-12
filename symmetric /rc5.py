import random
import struct


def rotl(x, y, w=32):
    y = y % w
    return ((x << y) | (x >> (w - y))) & ((1 << w) - 1)


def rotr(x, y, w=32):
    y = y % w
    return ((x >> y) | (x << (w - y))) & ((1 << w) - 1)


P = 0xB7E15163
Q = 0x9E3779B9


def key_expansion(key, w=32, r=12):
    b = len(key)
    u = w // 8
    c = max(1, (b + u - 1) // u)
    mask = (1 << w) - 1

    L = [0] * c

    for i in range(b - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) + key[i]) & mask

    S = [0] * (2 * (r + 1))
    S[0] = P

    nS = len(S)
    for i in range(1, nS):
        S[i] = (S[i - 1] + Q) & mask

    A = B = i = j = 0
    for _ in range(3 * max(nS, c)):
        A = S[i] = rotl((S[i] + A + B), 3, w)
        B = L[j] = rotl((L[j] + A + B), (A + B), w)
        i = (i + 1) % nS
        j = (j + 1) % c

    return S


def encrypt_block(A, B, S, w=32, r=12):
    mask = (1 << w) - 1
    A = (A + S[0]) & mask
    B = (B + S[1]) & mask
    for i in range(1, r + 1):
        A = (rotl(A ^ B, B, w) + S[2 * i]) & mask
        B = (rotl(B ^ A, A, w) + S[2 * i + 1]) & mask
    return A, B


def decrypt_block(A, B, S, w=32, r=12):
    mask = (1 << w) - 1
    for i in range(r, 0, -1):
        B = rotr((B - S[2 * i + 1]) & mask, A, w) ^ A
        A = rotr((A - S[2 * i]) & mask, B, w) ^ B
    B = (B - S[1]) & mask
    A = (A - S[0]) & mask
    return A, B


# ── Recommendation implementations ────────────────────────────────────────────

BLOCK_SIZE = 8  # 64-bit block = two 32-bit words = 8 bytes


def _pad(data: bytes) -> bytes:
    """
    PKCS#7 padding: append N bytes each with value N so the total
    length is a multiple of BLOCK_SIZE.  N is always in [1, BLOCK_SIZE].
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding added by _pad()."""
    if not data:
        raise ValueError("Empty data cannot be unpadded.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding is corrupt.")
    return data[:-pad_len]


def _bytes_to_blocks(data: bytes):
    """
    Split a byte string (already padded to a multiple of BLOCK_SIZE)
    into a list of (A, B) integer pairs ready for encrypt_block().
    Uses little-endian 32-bit words as specified by RC5.
    """
    blocks = []
    for offset in range(0, len(data), BLOCK_SIZE):
        chunk = data[offset : offset + BLOCK_SIZE]
        A, B = struct.unpack_from("<II", chunk)   # two LE 32-bit words
        blocks.append((A, B))
    return blocks


def _blocks_to_bytes(blocks) -> bytes:
    """Reassemble (A, B) integer pairs back into a byte string."""
    return b"".join(struct.pack("<II", A, B) for A, B in blocks)


def encrypt_message(plaintext: str, key: bytes, encoding: str = "utf-8") -> bytes:
    """
    Full pipeline: string → bytes → padding → 64-bit blocks → RC5 encryption.

    Args:
        plaintext: The human-readable message to encrypt.
        key:       Shared secret key (bytes).  Both parties must use the same key.
        encoding:  Text encoding used to convert the string to bytes.

    Returns:
        Raw ciphertext bytes ready for transmission.
    """
    S = key_expansion(key)
    raw = plaintext.encode(encoding)
    padded = _pad(raw)
    plain_blocks = _bytes_to_blocks(padded)
    cipher_blocks = [encrypt_block(A, B, S) for A, B in plain_blocks]
    return _blocks_to_bytes(cipher_blocks)


def decrypt_message(ciphertext: bytes, key: bytes, encoding: str = "utf-8") -> str:
    """
    Full pipeline: ciphertext bytes → 64-bit blocks → RC5 decryption → string.

    Args:
        ciphertext: Raw bytes received from the other party.
        key:        Shared secret key — must match the one used for encryption.
        encoding:   Text encoding used to decode the recovered plaintext bytes.

    Returns:
        The original plaintext string.
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length ({len(ciphertext)}) is not a multiple of {BLOCK_SIZE}."
        )
    S = key_expansion(key)
    cipher_blocks = _bytes_to_blocks(ciphertext)
    plain_blocks = [decrypt_block(A, B, S) for A, B in cipher_blocks]
    padded = _blocks_to_bytes(plain_blocks)
    raw = _unpad(padded)
    return raw.decode(encoding)


# ── Demo ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    KEY = b"secretkey"
    S = key_expansion(KEY)

    # ── Original low-level tests ───────────────────────────────────────────
    print("=== Low-level block tests ===")
    A, B = 123, 456
    cipher = encrypt_block(A, B, S)
    plain = decrypt_block(cipher[0], cipher[1], S)
    print("Encrypted:", cipher)
    print("Decrypted:", plain)

    A1, B1 = 123, 456
    A2, B2 = 124, 456
    c1 = encrypt_block(A1, B1, S)
    c2 = encrypt_block(A2, B2, S)
    print("Avalanche sample:", c1, c2)

    for _ in range(100):
        A = random.randint(0, 2**32 - 1)
        B = random.randint(0, 2**32 - 1)
        c = encrypt_block(A, B, S)
        p = decrypt_block(c[0], c[1], S)
        if p != (A, B):
            print("FAILED!")
            break
    else:
        print("All 100 random round-trips passed.")

    # ── Recommendation: full message pipeline ──────────────────────────────
    print("\n=== Full message pipeline (string → bytes → blocks → encrypt) ===")

    messages = [
        "Hello, World!",
        "Short",
        "This is a longer message that spans multiple 64-bit blocks.",
        "Exact16bytes!!!",          # exactly two blocks (no extra padding needed beyond 1 byte)
        "Unicode: مرحبا بالعالم",   # Arabic characters
    ]

    all_ok = True
    for msg in messages:
        ct = encrypt_message(msg, KEY)
        recovered = decrypt_message(ct, KEY)
        status = "OK" if recovered == msg else "FAIL"
        if status == "FAIL":
            all_ok = False
        print(f"  [{status}] original={msg!r}  ciphertext_hex={ct.hex()}")

    print("\nAll message round-trips passed." if all_ok else "Some tests FAILED!")

    # ── Simulated bidirectional exchange (Company A ↔ Company B) ──────────
    print("\n=== Simulated Company A ↔ Company B exchange ===")
    SHARED_KEY = b"super-secret-42!"   # must be exchanged securely (e.g. via ElGamal)

    # Company A encrypts
    message_from_A = "Transfer approved: $9,500"
    ciphertext = encrypt_message(message_from_A, SHARED_KEY)
    print(f"Company A sends (hex): {ciphertext.hex()}")

    # Company B decrypts
    message_at_B = decrypt_message(ciphertext, SHARED_KEY)
    print(f"Company B reads:       {message_at_B!r}")
    print("Round-trip matches:", message_from_A == message_at_B)
