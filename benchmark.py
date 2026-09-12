import time
import os
import sys
import tracemalloc

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from symmetric.rc5     import encrypt_message, decrypt_message
from symmetric.feistel import feistel_encrypt_bytes, feistel_decrypt_bytes

# ── Configuration ─────────────────────────────────────────────────────────────
KEY       = b"benchmarkkey1234"
SIZES     = [100, 1_000, 10_000, 100_000]   # plaintext sizes in bytes
REPEATS   = 5    # average over N runs to reduce noise

# ── Helpers ───────────────────────────────────────────────────────────────────

def _avg_time(fn, *args) -> float:
    """Return average wall-clock time in ms over REPEATS calls."""
    times = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        fn(*args)
        times.append((time.perf_counter() - t0) * 1000)
    return sum(times) / len(times)


def _peak_mem_kb(fn, *args) -> float:
    """Return peak memory delta in KB for a single call."""
    tracemalloc.start()
    fn(*args)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


def _bar(value, max_value, width=20) -> str:
    """Simple ASCII progress bar."""
    filled = int(round(value / max_value * width)) if max_value else 0
    return "█" * filled + "░" * (width - filled)


# ── Benchmark runner ──────────────────────────────────────────────────────────

def run_benchmarks():
    print("=" * 72)
    print("  Shegha Cryptographic Performance Benchmark")
    print(f"  Key length : {len(KEY)} bytes   |   Averaged over {REPEATS} runs each")
    print("=" * 72)

    results = []   # store for chart rendering later

    for n in SIZES:
        plaintext_bytes = os.urandom(n)
        plaintext_str   = plaintext_bytes.decode('latin-1')

        # ── RC5 ──────────────────────────────────────────────────────────────
        rc5_ct          = encrypt_message(plaintext_str, KEY)
        rc5_enc_ms      = _avg_time(encrypt_message, plaintext_str, KEY)
        rc5_dec_ms      = _avg_time(decrypt_message, rc5_ct, KEY)
        rc5_mem_kb      = _peak_mem_kb(encrypt_message, plaintext_str, KEY)
        rc5_ct_size     = len(rc5_ct)
        rc5_overhead    = (rc5_ct_size - n) / n * 100

        # ── Feistel ──────────────────────────────────────────────────────────
        feistel_ct      = feistel_encrypt_bytes(plaintext_bytes, KEY)
        feistel_enc_ms  = _avg_time(feistel_encrypt_bytes, plaintext_bytes, KEY)
        feistel_dec_ms  = _avg_time(feistel_decrypt_bytes, feistel_ct, KEY)
        feistel_mem_kb  = _peak_mem_kb(feistel_encrypt_bytes, plaintext_bytes, KEY)
        feistel_ct_size = len(feistel_ct)
        feistel_overhead= (feistel_ct_size - n) / n * 100

        results.append({
            "n": n,
            "rc5_enc": rc5_enc_ms,    "rc5_dec": rc5_dec_ms,
            "rc5_mem": rc5_mem_kb,    "rc5_ct":  rc5_ct_size,
            "rc5_ovr": rc5_overhead,
            "fst_enc": feistel_enc_ms,"fst_dec": feistel_dec_ms,
            "fst_mem": feistel_mem_kb,"fst_ct":  feistel_ct_size,
            "fst_ovr": feistel_overhead,
        })

        print(f"\n  Plaintext size : {n:>7} bytes")
        print(f"  {'Metric':<28} {'RC5':>12}  {'Feistel':>12}")
        print(f"  {'-'*28} {'-'*12}  {'-'*12}")
        print(f"  {'Encrypt time (ms)':<28} {rc5_enc_ms:>12.3f}  {feistel_enc_ms:>12.3f}")
        print(f"  {'Decrypt time (ms)':<28} {rc5_dec_ms:>12.3f}  {feistel_dec_ms:>12.3f}")
        print(f"  {'Peak memory (KB)':<28} {rc5_mem_kb:>12.1f}  {feistel_mem_kb:>12.1f}")
        print(f"  {'Ciphertext size (bytes)':<28} {rc5_ct_size:>12}  {feistel_ct_size:>12}")
        print(f"  {'Size overhead (%)':<28} {rc5_overhead:>11.1f}%  {feistel_overhead:>11.1f}%")

    # ── ASCII Chart: Encryption time vs input size ────────────────────────────
    print("\n" + "=" * 72)
    print("  Chart: Encryption time (ms) — RC5 vs Feistel")
    print("  (bar length proportional to time)")
    print("=" * 72)

    max_enc = max(max(r["rc5_enc"], r["fst_enc"]) for r in results)
    for r in results:
        label = f"{r['n']:>7}B"
        print(f"\n  {label}  RC5     {_bar(r['rc5_enc'], max_enc)}  {r['rc5_enc']:.2f} ms")
        print(f"  {'':>7}   Feistel {_bar(r['fst_enc'], max_enc)}  {r['fst_enc']:.2f} ms")

    # ── ASCII Chart: Ciphertext overhead ──────────────────────────────────────
    print("\n" + "=" * 72)
    print("  Chart: Ciphertext overhead (%) — how much larger than plaintext")
    print("=" * 72)
    max_ovr = max(max(r["rc5_ovr"], r["fst_ovr"]) for r in results) or 1
    for r in results:
        label = f"{r['n']:>7}B"
        print(f"\n  {label}  RC5     {_bar(r['rc5_ovr'], max_ovr)}  {r['rc5_ovr']:.1f}%")
        print(f"  {'':>7}   Feistel {_bar(r['fst_ovr'], max_ovr)}  {r['fst_ovr']:.1f}%")

    # ── Summary table ─────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("  Summary: which cipher is faster at each size?")
    print("=" * 72)
    print(f"  {'Size':>10}  {'Faster enc':>12}  {'Faster dec':>12}  {'Smaller ct':>12}")
    print(f"  {'-'*10}  {'-'*12}  {'-'*12}  {'-'*12}")
    for r in results:
        enc_w  = "RC5" if r["rc5_enc"] <= r["fst_enc"] else "Feistel"
        dec_w  = "RC5" if r["rc5_dec"] <= r["fst_dec"] else "Feistel"
        ct_w   = "RC5" if r["rc5_ct"]  <= r["fst_ct"]  else "Feistel"
        print(f"  {r['n']:>10}  {enc_w:>12}  {dec_w:>12}  {ct_w:>12}")

    print("\n" + "=" * 72)
    print("  Benchmark complete.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_benchmarks()