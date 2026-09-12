"""
feistel.py  –  Sheghaf Quantum Labs
======================================
A pure-Python, from-scratch Feistel block cipher for file encryption.
No cryptographic libraries used – only built-in math / bitwise operations.

Block layout
------------
  Block size : 8 bytes (64-bit)
  Half size  : 4 bytes (32-bit) per half  →  L || R
  Rounds     : 16  (configurable via ROUNDS constant)

Round function F(half, subkey)
-------------------------------
  1. XOR  the half with the subkey
  2. Multiply by a prime constant (mix bits without carry overflow)
  3. Rotate left by (subkey % 32) bits
  4. XOR with a second prime constant
  5. Return lower 32 bits

Key schedule
------------
  Derives ROUNDS independent 32-bit sub-keys from a raw key of any length
  using a simple, purely mathematical scheme:
    - Seed a 32-bit accumulator from each key byte
    - Mix using multiply-add-rotate steps
    - Each sub-key is different thanks to a round-dependent constant

Usage (stand-alone)
-------------------
  python feistel.py encrypt <key> <input_file> <output_file>
  python feistel.py decrypt <key> <input_file> <output_file>

Usage (as a module)
-------------------
  from feistel import encrypt_file, decrypt_file
  encrypt_file(b"my-secret-key", "photo.jpg",  "photo.jpg.enc")
  decrypt_file(b"my-secret-key", "photo.jpg.enc", "photo_recovered.jpg")
"""

import os
import struct
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
BLOCK_SIZE  = 8          # bytes  (64-bit block → two 32-bit halves)
HALF_SIZE   = BLOCK_SIZE // 2   # 4 bytes per half
ROUNDS      = 16         # number of Feistel rounds
MASK32      = 0xFFFFFFFF # keep arithmetic within 32 bits

# Two large prime-like constants used inside the round function
_PRIME_A = 0x9E3779B9   # golden-ratio-derived constant (same as RC5 uses)
_PRIME_B = 0x6C62272E   # FNV prime constant


# ─────────────────────────────────────────────────────────────────────────────
# Bit rotation helpers (32-bit)
# ─────────────────────────────────────────────────────────────────────────────

def _rotl32(value: int, shift: int) -> int:
    """Rotate a 32-bit integer left by `shift` positions."""
    shift &= 31           # keep in [0, 31]
    return ((value << shift) | (value >> (32 - shift))) & MASK32


def _rotr32(value: int, shift: int) -> int:
    """Rotate a 32-bit integer right by `shift` positions."""
    shift &= 31
    return ((value >> shift) | (value << (32 - shift))) & MASK32


# ─────────────────────────────────────────────────────────────────────────────
# Key schedule  –  produce ROUNDS independent 32-bit sub-keys
# ─────────────────────────────────────────────────────────────────────────────

def _derive_subkeys(key: bytes, rounds: int = ROUNDS):
    """
    Pure-math key schedule.  No crypto library used.

    Algorithm:
      acc  starts at _PRIME_A
      For each key byte b:
          acc = rotl32( (acc XOR b) * _PRIME_B,  b % 32 ) & MASK32
      Then for each round r:
          subkey[r] = rotl32( acc * (r + _PRIME_A),  r % 32 ) & MASK32
          acc       = rotl32( acc + subkey[r],        5       ) & MASK32
    """
    if not key:
        raise ValueError("Key must be at least 1 byte long.")

    acc = _PRIME_A
    for b in key:
        acc = _rotl32(((acc ^ b) * _PRIME_B) & MASK32, b % 32)

    subkeys = []
    for r in range(rounds):
        sk = _rotl32((acc * ((r + 1) + _PRIME_A)) & MASK32, r % 32)
        subkeys.append(sk)
        acc = _rotl32((acc + sk) & MASK32, 5)

    return subkeys


# ─────────────────────────────────────────────────────────────────────────────
# Feistel round function  F(half, subkey) → 32-bit output
# ─────────────────────────────────────────────────────────────────────────────

def _F(half: int, subkey: int) -> int:
    """
    Non-linear mixing function.
    Inputs and output are 32-bit unsigned integers.

    Steps:
      1. XOR with subkey
      2. Multiply by _PRIME_A  (introduces non-linearity / avalanche)
      3. Rotate left by (subkey % 32)
      4. XOR with _PRIME_B
    """
    x = (half ^ subkey) & MASK32
    x = (x * _PRIME_A) & MASK32
    x = _rotl32(x, subkey % 32)
    x = (x ^ _PRIME_B) & MASK32
    return x


# ─────────────────────────────────────────────────────────────────────────────
# Single-block encrypt / decrypt  (operates on two 32-bit integers)
# ─────────────────────────────────────────────────────────────────────────────

def _encrypt_block(L: int, R: int, subkeys) -> tuple:
    """
    Encrypt one 64-bit block represented as (L, R) – each a 32-bit integer.

    Feistel network (ROUNDS rounds):
        for i in 0 .. ROUNDS-1:
            new_R = L XOR F(R, subkeys[i])
            new_L = R
    """
    for i in range(ROUNDS):
        new_R = (L ^ _F(R, subkeys[i])) & MASK32
        L = R
        R = new_R
    return L, R


def _decrypt_block(L: int, R: int, subkeys) -> tuple:
    """
    Decrypt one 64-bit block.
    Uses the same sub-keys in REVERSE order – no extra key material needed.
    """
    for i in range(ROUNDS - 1, -1, -1):
        new_L = (R ^ _F(L, subkeys[i])) & MASK32
        R = L
        L = new_L
    return L, R


# ─────────────────────────────────────────────────────────────────────────────
# Padding  (PKCS#7 style for 8-byte blocks)
# ─────────────────────────────────────────────────────────────────────────────

def _pad(data: bytes) -> bytes:
    """Append N bytes each with value N so len(result) % BLOCK_SIZE == 0."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding. Raises ValueError on corrupt padding."""
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Bad padding byte: {pad_len!r}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding is corrupt – wrong key or tampered data.")
    return data[:-pad_len]


# ─────────────────────────────────────────────────────────────────────────────
# Byte-level encrypt / decrypt  (bytes in → bytes out)
# ─────────────────────────────────────────────────────────────────────────────

def feistel_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt arbitrary bytes with the Feistel cipher.

    Pipeline:
        plaintext → PKCS#7 pad → split into 8-byte blocks
        → encrypt each block → concatenate → ciphertext
    """
    subkeys = _derive_subkeys(key)
    padded  = _pad(plaintext)
    output  = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        chunk = padded[offset : offset + BLOCK_SIZE]
        L, R  = struct.unpack('>II', chunk)   # big-endian 32-bit pair
        eL, eR = _encrypt_block(L, R, subkeys)
        output += struct.pack('>II', eL, eR)

    return bytes(output)


def feistel_decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt bytes produced by feistel_encrypt_bytes().

    Pipeline:
        ciphertext → split into 8-byte blocks → decrypt each block
        → concatenate → remove PKCS#7 padding → plaintext
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length {len(ciphertext)} is not a multiple of {BLOCK_SIZE}."
        )
    subkeys = _derive_subkeys(key)
    output  = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        chunk = ciphertext[offset : offset + BLOCK_SIZE]
        L, R  = struct.unpack('>II', chunk)
        dL, dR = _decrypt_block(L, R, subkeys)
        output += struct.pack('>II', dL, dR)

    return _unpad(bytes(output))


# ─────────────────────────────────────────────────────────────────────────────
# File-level API  –  the main interface for eve-chat.py
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file(key: bytes, input_path: str, output_path: str) -> dict:
    """
    Read a file, encrypt it with the Feistel cipher, and write the result.

    Returns a metadata dict:
        {
          "original_filename" : str,
          "original_size"     : int,   # bytes
          "encrypted_size"    : int,   # bytes (always >= original_size)
          "block_count"       : int,
          "rounds"            : int,
        }

    The output file format:
        [8-byte magic header "FEISTEL1"]
        [4-byte big-endian original file size]
        [ciphertext blocks …]
    """
    MAGIC = b"FEISTEL1"   # 8-byte file signature for integrity checking

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    original_size = len(plaintext)
    ciphertext    = feistel_encrypt_bytes(plaintext, key)

    with open(output_path, 'wb') as f:
        f.write(MAGIC)
        f.write(struct.pack('>I', original_size))   # 4 bytes: original size
        f.write(ciphertext)

    return {
        "original_filename" : os.path.basename(input_path),
        "original_size"     : original_size,
        "encrypted_size"    : len(ciphertext),
        "block_count"       : len(ciphertext) // BLOCK_SIZE,
        "rounds"            : ROUNDS,
    }


def decrypt_file(key: bytes, input_path: str, output_path: str) -> dict:
    """
    Read a Feistel-encrypted file, decrypt it, and write the original content.

    Returns a metadata dict:
        {
          "recovered_size"  : int,   # bytes written
          "encrypted_size"  : int,   # ciphertext bytes read
          "block_count"     : int,
          "rounds"          : int,
        }

    Raises ValueError if the magic header is missing (wrong file or key).
    """
    MAGIC = b"FEISTEL1"
    HEADER_SIZE = len(MAGIC) + 4   # 8 + 4 = 12 bytes

    with open(input_path, 'rb') as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise ValueError("File too short – not a valid Feistel-encrypted file.")

        magic = header[:8]
        if magic != MAGIC:
            raise ValueError(
                f"Bad magic header {magic!r}. Is this a Feistel-encrypted file?"
            )
        original_size = struct.unpack('>I', header[8:12])[0]
        ciphertext    = f.read()

    plaintext = feistel_decrypt_bytes(ciphertext, key)

    # Sanity-check the recovered size matches what was stored in the header
    if len(plaintext) != original_size:
        raise ValueError(
            f"Size mismatch after decryption: expected {original_size} bytes, "
            f"got {len(plaintext)} bytes. Wrong key?"
        )

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return {
        "recovered_size" : len(plaintext),
        "encrypted_size" : len(ciphertext),
        "block_count"    : len(ciphertext) // BLOCK_SIZE,
        "rounds"         : ROUNDS,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

def _run_self_tests():
    print("=" * 55)
    print("  Feistel Cipher – Sheghaf Quantum Labs  |  Self-Test")
    print("=" * 55)

    KEY = b"sheghaf-quantum-labs"

    # ── 1. Single-block level ─────────────────────────────────────────────
    print("\n[1] Block-level round-trip tests")
    subkeys = _derive_subkeys(KEY)
    test_pairs = [
        (0x00000000, 0x00000000),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xDEADBEEF, 0xCAFEBABE),
        (0x12345678, 0x9ABCDEF0),
        (0x00000001, 0x00000001),
    ]
    all_ok = True
    for L, R in test_pairs:
        eL, eR = _encrypt_block(L, R, subkeys)
        dL, dR = _decrypt_block(eL, eR, subkeys)
        ok = (dL == L and dR == R)
        if not ok:
            all_ok = False
        print(f"  L={L:#010x} R={R:#010x} → enc=({eL:#010x},{eR:#010x}) "
              f"→ dec=({'OK' if ok else 'FAIL'})")
    print("  All block tests passed." if all_ok else "  SOME BLOCK TESTS FAILED!")

    # ── 2. Byte-level round-trips ─────────────────────────────────────────
    print("\n[2] Byte-level round-trip tests")
    byte_cases = [
        b"Hello, Sheghaf!",
        b"\x00\x01\x02\x03",
        b"A" * 64,
        bytes(range(256)),
        b"Exact8b!",           # exactly one block
        b"Transfer: $9,500",
    ]
    for data in byte_cases:
        ct = feistel_encrypt_bytes(data, KEY)
        pt = feistel_decrypt_bytes(ct, KEY)
        ok = (pt == data)
        if not ok:
            all_ok = False
        print(f"  [{len(data):>4}B] {data[:24]!r:<28} → {'OK' if ok else 'FAIL'}")

    # ── 3. Avalanche effect demo ──────────────────────────────────────────
    print("\n[3] Avalanche effect (1-bit change in L)")
    L1, R1 = 0x12345678, 0x9ABCDEF0
    L2, R2 = L1 ^ 1,     R1          # flip LSB of L
    eL1, eR1 = _encrypt_block(L1, R1, subkeys)
    eL2, eR2 = _encrypt_block(L2, R2, subkeys)

    def _count_bit_diffs(a, b):
        diff = a ^ b
        return bin(diff).count('1')

    diffs = _count_bit_diffs(eL1, eL2) + _count_bit_diffs(eR1, eR2)
    print(f"  Plain  pair : ({L1:#010x}, {R1:#010x})")
    print(f"  Cipher pair1: ({eL1:#010x}, {eR1:#010x})")
    print(f"  Cipher pair2: ({eL2:#010x}, {eR2:#010x})")
    print(f"  Bit differences in ciphertext: {diffs} / 64")

    # ── 4. File round-trip ────────────────────────────────────────────────
    print("\n[4] File-level round-trip test")
    import tempfile
    SAMPLE_CONTENT = (
        b"Sheghaf Quantum Labs - Feistel file encryption test.\n"
        b"Binary: " + bytes(range(256)) +
        b"\nEnd of test payload."
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tf:
        plain_path = tf.name
        tf.write(SAMPLE_CONTENT)

    enc_path = plain_path + ".feistel"
    dec_path = plain_path + ".recovered"

    try:
        enc_meta = encrypt_file(KEY, plain_path, enc_path)
        dec_meta = decrypt_file(KEY, enc_path,   dec_path)

        with open(dec_path, 'rb') as f:
            recovered = f.read()

        file_ok = (recovered == SAMPLE_CONTENT)
        print(f"  Original size  : {enc_meta['original_size']} bytes")
        print(f"  Encrypted size : {enc_meta['encrypted_size']} bytes  "
              f"({enc_meta['block_count']} blocks × {BLOCK_SIZE} B, "
              f"{ROUNDS} rounds)")
        print(f"  Recovered size : {dec_meta['recovered_size']} bytes")
        print(f"  Content match  : {'YES ✓' if file_ok else 'NO ✗  ← FAIL'}")
        if not file_ok:
            all_ok = False
    finally:
        for p in (plain_path, enc_path, dec_path):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass

    print("\n" + ("=" * 55))
    print("  ALL TESTS PASSED ✓" if all_ok else "  SOME TESTS FAILED ✗")
    print("=" * 55)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] == "test":
        _run_self_tests()
        sys.exit(0)

    if len(args) != 4 or args[0] not in ("encrypt", "decrypt"):
        print("Usage:")
        print("  python feistel.py test")
        print("  python feistel.py encrypt <key> <input_file> <output_file>")
        print("  python feistel.py decrypt <key> <input_file> <output_file>")
        sys.exit(1)

    mode, key_str, in_file, out_file = args
    key_bytes = key_str.encode()

    try:
        if mode == "encrypt":
            meta = encrypt_file(key_bytes, in_file, out_file)
            print(f"[Feistel] Encrypted '{in_file}' → '{out_file}'")
            print(f"          {meta['original_size']} B → {meta['encrypted_size']} B  "
                  f"| {meta['block_count']} blocks | {meta['rounds']} rounds")
        else:
            meta = decrypt_file(key_bytes, in_file, out_file)
            print(f"[Feistel] Decrypted '{in_file}' → '{out_file}'")
            print(f"          Recovered {meta['recovered_size']} bytes "
                  f"| {meta['block_count']} blocks | {meta['rounds']} rounds")
    except FileNotFoundError as e:
        print(f"[Error] File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[Error] {e}")
        sys.exit(1)