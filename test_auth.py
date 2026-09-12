"""
test_auth.py — NTRU-401 Authentication Security Demonstration
=============================================================
Tests all attack scenarios required by the assignment:

  1. Honest flow          – legitimate sign-verify succeeds
  2. Replay attack        – re-using an old challenge-response is rejected
  3. Wrong-key attack     – adversary with a different f is blocked
  4. Identity mismatch    – signature for "bob" rejected under "alice" vk
  5. Tampered response    – flipped coefficient in signature is rejected
  6. Zero / null response – empty or zero polynomial is rejected

Run from ~/CryptOo/crypto:
    python3 test_auth.py
"""
import sys, time
sys.path.append('.')
from pqc.NTRU import (
    generate_keypair, NTRUAuthenticator,
    sign_challenge, verify_keypair,
    encode_message, decode_message, encrypt, decrypt,
    D_F_PLUS, D_F_MINUS, D_G, N, P, Q,
    _generate_ternary_asym,     # private — not exported by import *
)

# ── ANSI colours ──────────────────────────────────────────────────────────────
_G   = "\033[38;2;93;202;165m"    # green
_R   = "\033[38;2;226;75;74m"     # red
_W   = "\033[38;2;239;159;39m"    # orange / warn
_B   = "\033[38;2;55;138;221m"    # blue / info
_MUT = "\033[38;2;180;178;169m"   # muted
_RST = "\033[0m"
_BLD = "\033[1m"

SEP  = "═" * 64
SEP2 = "─" * 64

def _ok(label):  print(f"    {_G}✔  {label}{_RST}")
def _fail(label):print(f"    {_R}✗  {label}{_RST}")
def _warn(label):print(f"    {_W}⚠  {label}{_RST}")
def _info(label):print(f"    {_B}ℹ  {label}{_RST}")

def _header(title):
    print(f"\n{SEP2}")
    print(f"  {_BLD}{title}{_RST}")
    print(SEP2)

def _assert(cond, pass_msg, fail_msg):
    if cond:
        _ok(pass_msg)
    else:
        _fail(fail_msg)
    return cond

# ── Setup ─────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"  {_BLD}NTRU-401 Security Test Suite{_RST}")
print(f"  {_MUT}Cryptographic authentication layer — all attack scenarios{_RST}")
print(SEP)

print("\n  Generating key pairs … (may take a few seconds)\n")
t0 = time.time()
alice_priv, alice_pub, alice_reg, att1 = generate_keypair(user_id="alice")
bob_priv,   bob_pub,   bob_reg,   att2 = generate_keypair(user_id="bob")
elapsed = time.time() - t0
_info(f"alice keygen: {att1} attempt(s)")
_info(f"bob   keygen: {att2} attempt(s)")
_info(f"Total elapsed: {elapsed:.2f}s")

# ── 0: Key pair algebraic consistency ─────────────────────────────────────────
_header("0 — Key Pair Algebraic Consistency")
res = verify_keypair(alice_priv, alice_pub)
_assert(res["fp_ok"], "f · f_p ≡ 1 (mod P)   ← decryption works",
                      "f · f_p FAILED")
_assert(res["fq_ok"], "f · f_q ≡ 1 (mod Q)   ← public key valid",
                      "f · f_q FAILED")
_assert(res["h_ok"],  "h · f  ≡ P·g (mod Q)  ← public key formula OK",
                      "h · f  FAILED")

# ── 1: Honest authentication flow ─────────────────────────────────────────────
_header("1 — Honest Authentication (5 rounds)")
passed = 0
ROUNDS = 5
for i in range(1, ROUNDS + 1):
    srv = NTRUAuthenticator(registration_data=alice_reg)
    cli = NTRUAuthenticator(private_key=alice_priv, public_key=alice_pub)
    nonce    = srv.create_challenge()
    response = cli.respond_to_challenge(nonce)
    ok       = srv.check_response(response)
    if ok:
        passed += 1
    _assert(ok,
            f"Round {i}: nonce={nonce}  →  AUTHENTICATED",
            f"Round {i}: nonce={nonce}  →  FAILED (should not happen)")
_assert(passed == ROUNDS,
        f"All {ROUNDS}/{ROUNDS} honest rounds passed",
        f"Only {passed}/{ROUNDS} passed — BUG")

# ── 2: Replay attack — reuse an old (nonce, response) pair ───────────────────
_header("2 — Replay Attack  (reuse old challenge-response)")
_info("Attacker captures a valid (nonce, response) pair and replays it")
srv      = NTRUAuthenticator(registration_data=alice_reg)
cli      = NTRUAuthenticator(private_key=alice_priv, public_key=alice_pub)
nonce1   = srv.create_challenge()
response = cli.respond_to_challenge(nonce1)
ok1      = srv.check_response(response)           # legitimate round
_assert(ok1, "Original response accepted (baseline)", "Original response FAILED")

# Now the server issues a NEW nonce — attacker replays the old response
srv2 = NTRUAuthenticator(registration_data=alice_reg)
nonce2 = srv2.create_challenge()
# The nonce is different ⟹ the hash_to_poly(user_id, nonce2) is different
# ⟹ h*s ≠ vk*c  ⟹ verification fails
ok_replay = srv2.check_response(response)          # replayed response
_assert(not ok_replay,
        "Replayed response REJECTED  ← anti-replay holds",
        "Replayed response ACCEPTED  ← SECURITY BREACH")
_assert(nonce1 != nonce2,
        f"Nonces differ ({nonce1} ≠ {nonce2})  ← fresh challenge per round",
        "Nonces were equal — RNG collision (re-run)")

# ── 3: Wrong-key attack — adversary generates a fresh random f ───────────────
_header("3 — Wrong-Key Attack  (adversary has different f)")
_info("Adversary has no access to alice's f — uses a randomly generated one")
TRIALS = 5
blocked = 0
for i in range(1, TRIALS + 1):
    srv      = NTRUAuthenticator(registration_data=alice_reg)
    nonce    = srv.create_challenge()
    atk_f    = _generate_ternary_asym(D_F_PLUS, D_F_MINUS)
    atk_resp = sign_challenge({"f": atk_f}, "alice", nonce)
    ok       = srv.check_response(atk_resp)
    if not ok:
        blocked += 1
    _assert(not ok,
            f"Attempt {i}: BLOCKED  ← wrong-key signature rejected",
            f"Attempt {i}: ACCEPTED  ← SECURITY BREACH")
_assert(blocked == TRIALS,
        f"All {TRIALS}/{TRIALS} adversary attempts blocked",
        f"Only {blocked}/{TRIALS} blocked — BUG")

# ── 4: Identity mismatch — bob's key signed under alice's user_id ─────────────
_header("4 — Identity Mismatch  (cross-user replay)")
_info("Bob signs with his own f but presents response under alice's identity")
srv   = NTRUAuthenticator(registration_data=alice_reg)   # alice's registration
nonce = srv.create_challenge()
# Bob signs using *alice*'s user_id string (cross-user attempt)
bob_resp_as_alice = sign_challenge(bob_priv, "alice", nonce)
ok = srv.check_response(bob_resp_as_alice)
_assert(not ok,
        "Bob's key rejected under alice's vk  ← identity binding works",
        "Bob's key accepted under alice's vk  ← IDENTITY BREACH")

# Extra: bob can still authenticate under his own registration
srv_bob   = NTRUAuthenticator(registration_data=bob_reg)
nonce_bob = srv_bob.create_challenge()
bob_resp  = sign_challenge(bob_priv, "bob", nonce_bob)
ok_bob    = srv_bob.check_response(bob_resp)
_assert(ok_bob,
        "Bob authenticates correctly under his own vk  ← baseline OK",
        "Bob's own auth failed — BUG")

# ── 5: Tampered response — single flipped coefficient ─────────────────────────
_header("5 — Tampered Response  (bit-flip in signature)")
_info("Network attacker flips one coefficient of the signature polynomial")
srv      = NTRUAuthenticator(registration_data=alice_reg)
cli      = NTRUAuthenticator(private_key=alice_priv, public_key=alice_pub)
nonce    = srv.create_challenge()
response = cli.respond_to_challenge(nonce)

# Flip the first non-zero coefficient
tampered = response[:]
for i, c in enumerate(tampered):
    if c != 0:
        tampered[i] = -c        # flip sign
        break
ok = srv.check_response(tampered)
_assert(not ok,
        "Tampered signature REJECTED  ← integrity check holds",
        "Tampered signature ACCEPTED  ← SECURITY BREACH")

# ── 6: Null / zero response ───────────────────────────────────────────────────
_header("6 — Null / Zero Response  (degenerate input)")
_info("Attacker sends an all-zero polynomial as a 'response'")
srv      = NTRUAuthenticator(registration_data=alice_reg)
_nonce   = srv.create_challenge()
zero_resp = [0] * N
ok = srv.check_response(zero_resp)
_assert(not ok,
        "Zero response REJECTED  ← trivial input check holds",
        "Zero response ACCEPTED  ← SECURITY BREACH")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"  {_BLD}All NTRU-401 security tests complete{_RST}")
print(f"  {_MUT}Security relies on the hardness of the NTRU lattice problem,{_RST}")
print(f"  {_MUT}believed to be resistant to known quantum attacks (not proven).{_RST}")
print(SEP + "\n")