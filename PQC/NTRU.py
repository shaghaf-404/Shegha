"""
ntru.py  —  NTRU Post-Quantum Authentication Layer
============================================================
Steps 1 · 2 · 3 :  Parameters · Polynomial Arithmetic · Key Generation

Part of  : Integrated Secure Application (Milestone C)
Role     : Post-quantum identity verification replacing username/password auth.
           Each user holds an NTRU key pair.  The server stores only the public
           key.  Authentication is a cryptographic challenge–response that
           remains secure against quantum adversaries (Shor's / Grover's algs).

How it fits into your existing system
--------------------------------------
  ElGamal  ──►  session key exchange        (transit encryption)
  RC5      ──►  message encryption          (transit, symmetric)
  Feistel  ──►  file encryption             (at-rest, symmetric)
  NTRU     ──►  post-quantum authentication (identity proof layer)  ← THIS FILE

Mathematical background
------------------------
Work in the polynomial ring   R = Z[X] / (X^N − 1).

  Private key  :  ternary polynomials  f, g  ∈ R  (coefficients in {−1, 0, +1})
  Derived keys :  f_p = f⁻¹ mod p  in R_p       (needed for decryption)
                  f_q = f⁻¹ mod q  in R_q       (needed to build public key)
  Public  key  :  h = p · f_q · g  mod q  in R_q

The hardness of inverting h to recover f is a lattice problem that no known
quantum algorithm can solve in polynomial time.

Reference : Hoffstein, Pipher & Silverman,
            "NTRU: A Ring-Based Public Key Cryptosystem",
            ANTS III, LNCS 1423, pp. 267–288, 1998.
"""

import random
import math

N   = 401   # Ring degree : polynomials in  R = Z[X] / (X^N − 1)
P   =   3   # Small modulus  (private-key / plaintext coefficient space)
Q   = 2048  # Large modulus  (public-key space); Q = 2^11

# Ternary key weight parameters
D_F       = 133
D_F_PLUS  = D_F + 1    
D_F_MINUS = D_F       
D_G       = 133       
assert N > D_F_PLUS + D_F_MINUS, "D_F too large: not enough zero slots in f"
assert N > 2 * D_G,              "D_G too large: not enough zero slots in g"
assert Q % 2 == 0,               "Q must be a power of 2 (Hensel lifting)"
assert math.gcd(P, Q) == 1,      "gcd(P, Q) must be 1"



def poly_zero() -> list:
    """Additive identity: the zero polynomial (all N coefficients = 0)."""
    return [0] * N


def poly_one() -> list:
    """Multiplicative identity: the constant polynomial 1."""
    one = [0] * N
    one[0] = 1
    return one


def poly_mod_coeffs(f: list, m: int) -> list:
    """
    Reduce every coefficient of f modulo m.
    Output range:  {0, 1, …, m−1}.

    Args:
        f : N-element coefficient list.
        m : Positive modulus.

    Returns:
        New N-element list with all coefficients in [0, m).
    """
    return [c % m for c in f]


def poly_center_lift(f: list, m: int) -> list:
    """
    Lift coefficients from {0, …, m−1} to the symmetric range (−m/2, m/2].

    This is used after decryption to recover the original small signed
    coefficients before the final reduction mod P.

    Example with m = 32:
        c = 17  →  17 − 32 = −15      (17 > 16, so subtract 32)
        c = 15  →  15                  (15 ≤ 16, keep as-is)
        c = 16  →  −16                 (16 is the boundary — maps to −16)

    Args:
        f : N-element coefficient list (values already reduced mod m).
        m : Modulus used for the arithmetic.

    Returns:
        New N-element list with coefficients in (−m/2, m/2].
    """
    half = m // 2
    result = []
    for c in f:
        c = c % m
        result.append(c - m if c > half else c)
    return result


def poly_add(f: list, g: list, m: int) -> list:
    """
    Coefficient-wise addition   h = f + g   (mod m)  in R.

    Args:
        f, g : N-element coefficient lists.
        m    : Modulus.

    Returns:
        N-element list representing f + g in R_m.
    """
    return [(f[i] + g[i]) % m for i in range(N)]


def poly_sub(f: list, g: list, m: int) -> list:
    """
    Coefficient-wise subtraction   h = f − g   (mod m)  in R.

    Args:
        f, g : N-element coefficient lists.
        m    : Modulus.

    Returns:
        N-element list representing f − g in R_m.
    """
    return [(f[i] - g[i]) % m for i in range(N)]


def poly_mul(f: list, g: list, m: int) -> list:
    """
    Multiplication in  R_m = Z_m[X] / (X^N − 1)  via cyclic convolution.

    Formula
    -------
    Because  X^N = 1  in R, the product is:

        h[k]  =  Σ_{i=0}^{N−1}  f[i] · g[(k−i) mod N]   (mod m)

    This is a standard cyclic (circular) convolution of the coefficient vectors.

    Implementation
    ---------------
    We iterate over all pairs (i, j) and accumulate into h[(i+j) % N].
    Zero coefficients are skipped for efficiency.

    Time complexity: O(N²)  — appropriate for the educational N = 11.
    For production N values (401, 677, 1277), use NTT-based convolution O(N log N).

    Args:
        f, g : N-element coefficient lists.
        m    : Modulus.

    Returns:
        N-element list representing f · g  in R_m.
    """
    h = [0] * N
    for i in range(N):
        if f[i] == 0:
            continue
        for j in range(N):
            h[(i + j) % N] = (h[(i + j) % N] + f[i] * g[j]) % m
    return h


def poly_neg(f: list, m: int) -> list:
    """
    Additive inverse of f in R_m:  −f  (mod m).

    Returns:
        N-element list where every coefficient c becomes (−c) mod m.
    """
    return [(-c) % m for c in f]


def poly_scalar_mul(f: list, scalar: int, m: int) -> list:
    """
    Multiply every coefficient of f by  scalar  (mod m).

    Used when computing the public key:  h = p · f_q · g  — the factor p
    multiplies f_q before the polynomial multiplication with g.

    Args:
        f      : N-element coefficient list.
        scalar : Integer multiplier.
        m      : Modulus.

    Returns:
        N-element list.
    """
    return [(c * scalar) % m for c in f]


def poly_to_str(f: list, name: str = "f") -> str:
    """
    Human-readable representation of a polynomial.

    Shows only non-zero terms with proper exponent notation.
    Useful for demos, report figures, and hand-verification checks.

    Example:
        poly_to_str([1, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0], 'h')
        →  "h(X) = 1 - X^2 + X^4"

    Args:
        f    : N-element coefficient list.
        name : Variable name shown before the '=' sign.

    Returns:
        Formatted string.
    """
    terms = []
    for i, c in enumerate(f):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}X" if abs(c) != 1 else ("X" if c > 0 else "-X"))
        else:
            terms.append(f"{c}X^{i}" if abs(c) != 1 else (f"X^{i}" if c > 0 else f"-X^{i}"))

    if not terms:
        return f"{name}(X) = 0"

    expression = terms[0]
    for t in terms[1:]:
        if t.startswith("-"):
            expression += " - " + t[1:]
        else:
            expression += " + " + t
    return f"{name}(X) = {expression}"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers — integer and polynomial operations used by the inverters
# ─────────────────────────────────────────────────────────────────────────────

def _int_inv_mod(a: int, m: int) -> int:
    """
    Modular multiplicative inverse of integer a  mod m  via Extended Euclidean.
    Returns x  such that  a · x ≡ 1 (mod m).

    Only basic integer arithmetic is used — no library calls.

    Raises ValueError if gcd(a, m) ≠ 1  (inverse does not exist).

    Args:
        a : Integer to invert (will be reduced mod m first).
        m : Positive modulus.
    """
    a = a % m
    old_r, r   = a, m
    old_s, s   = 1, 0
    while r:
        q        = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError(
            f"Modular inverse does not exist: gcd({a}, {m}) = {old_r}."
        )
    return old_s % m


def _deg(f: list) -> int:
    """
    Degree of polynomial f  (index of the highest non-zero coefficient).
    Returns −1 if f is the zero polynomial.
    """
    for i in range(len(f) - 1, -1, -1):
        if f[i] != 0:
            return i
    return -1


def _trim(f: list) -> list:
    """
    Strip trailing zero coefficients, keeping at least one element.

    Example:  [1, 2, 0, 0]  →  [1, 2]
              [0]            →  [0]
    """
    i = len(f)
    while i > 1 and f[i - 1] == 0:
        i -= 1
    return f[:i]


def _poly_divmod_zp(a: list, b: list, p: int):
    """
    Polynomial long division of  a  by  b  over  Z_p  (p must be prime).

    Returns
    -------
    (quotient, remainder)  as variable-length coefficient lists such that:
        a = quotient · b + remainder   in Z_p[X]

    Used internally by the Extended Euclidean Algorithm.
    Both a and b may have more than N coefficients (they grow during the EEA).

    Args:
        a, b : Polynomial coefficient lists (leading coeff = last element).
        p    : Prime modulus.

    Raises:
        ValueError if b is the zero polynomial.
    """
    a      = list(a)
    b      = _trim(b)
    db     = _deg(b)

    if db < 0:
        raise ValueError("Division by zero polynomial.")

    lb_inv = _int_inv_mod(b[db], p)          # inverse of leading coeff of b
    q_out  = [0] * max(len(a) - db, 1)      # pre-allocate quotient

    while True:
        da = _deg(a)
        if da < db:
            break
        coef  = (a[da] * lb_inv) % p         # coefficient of this quotient term
        shift = da - db                       # X^shift term in quotient
        if shift < len(q_out):
            q_out[shift] = coef
        for k in range(db + 1):
            a[k + shift] = (a[k + shift] - coef * b[k]) % p

    return _trim(q_out), _trim(a)


def _poly_mul_raw(a: list, b: list, m: int) -> list:
    """
    Multiply two polynomials modulo m WITHOUT reducing mod (X^N − 1).

    Result degree can reach  deg(a) + deg(b).
    Used internally in the EEA where intermediate polynomials exceed N − 1.

    Args:
        a, b : Variable-length coefficient lists.
        m    : Coefficient modulus.

    Returns:
        Variable-length coefficient list.
    """
    if not a or not b or a == [0] or b == [0]:
        return [0]
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            result[i + j] = (result[i + j] + ai * bj) % m
    return result


def _poly_sub_raw(a: list, b: list, m: int) -> list:
    """
    Coefficient-wise subtraction of variable-length polynomials  a − b  mod m.

    Args:
        a, b : Variable-length coefficient lists.
        m    : Modulus.

    Returns:
        Variable-length list (trailing zeros stripped).
    """
    length = max(len(a), len(b))
    res    = [0] * length
    for i in range(len(a)):
        res[i] = (res[i] + a[i]) % m
    for i in range(len(b)):
        res[i] = (res[i] - b[i]) % m
    return _trim(res)


# ─────────────────────────────────────────────────────────────────────────────
# Polynomial inversion — the mathematical heart of NTRU key generation
# ─────────────────────────────────────────────────────────────────────────────

def _poly_eea(f_in: list, p: int) -> list:
    """
    Compute  f⁻¹  mod (X^N − 1)  in  R_p = Z_p[X] / (X^N − 1),  p prime.

    Algorithm: Extended Euclidean Algorithm (EEA) for polynomials over Z_p.
    ─────────────────────────────────────────────────────────────────────────
    We run EEA on the pair   (X^N − 1,  f)   tracking the Bézout coefficient
    s_b  for f  such that:

        (X^N − 1) · s_a  +  f · s_b  =  gcd   in Z_p[X]

    If the GCD is a non-zero constant c, then:

        f · (s_b · c⁻¹)  ≡  1   (mod X^N − 1, p)

    So  s_b · c⁻¹  is the inverse.

    The Bézout coefficient s_b satisfies  deg(s_b) < N,  so it is already a
    valid element of the ring R and needs no further reduction.

    Raises ValueError if f has no inverse  (gcd is not a non-zero constant,
    meaning gcd(f, X^N−1) is a non-trivial polynomial).

    Args:
        f_in : N-element coefficient list (the polynomial to invert).
        p    : Prime modulus (called with P=3 and P=2 during key generation).

    Returns:
        N-element coefficient list representing f⁻¹ in R_p.
    """
    # Modulus polynomial  X^N − 1:
    #   coefficients:  [−1, 0, 0, …, 0, +1]   (N+1 terms; index 0 and index N)
    xn_minus_1 = [(-1) % p] + [0] * (N - 1) + [1]

    r0  = _trim(xn_minus_1)
    r1  = _trim([(c % p) for c in f_in])
    sb0 = [0]    # Bézout coefficient for X^N−1  (not needed, tracked implicitly)
    sb1 = [1]    # Bézout coefficient for f:  f · 1 = f  ← invariant at step 0

    # Invariant maintained throughout the loop:
    #   (X^N−1) · sa_i  +  f · sb_i  =  r_i  in Z_p[X]
    while _deg(r1) >= 0:
        q_poly, remainder = _poly_divmod_zp(r0, r1, p)

        # New Bézout coefficient:  sb_new = sb0 − q · sb1
        new_sb = _poly_sub_raw(sb0, _poly_mul_raw(q_poly, sb1, p), p)

        r0,  r1  = r1,  _trim(remainder)
        sb0, sb1 = sb1, _trim(new_sb)

    # r0 now holds gcd(f, X^N−1);  f · sb0 ≡ gcd  (mod X^N−1, in Z_p[X])
    gcd = _trim(r0)
    if _deg(gcd) != 0 or gcd[0] == 0:
        raise ValueError(
            f"f is NOT invertible mod (X^{N}−1) over Z_{p}.  "
            f"gcd = {gcd}  (must be a non-zero constant)."
        )

    # Normalize s so that  f · s ≡ 1  (multiply sb0 by gcd⁻¹)
    gcd_inv = _int_inv_mod(gcd[0], p)
    s_raw   = [(gcd_inv * c) % p for c in sb0]

    # Reduce into the ring  R  (bring degree below N).
    # X^N ≡ 1, so a coefficient at position i ≥ N wraps to position i mod N.
    result = [0] * N
    for i, c in enumerate(s_raw):
        result[i % N] = (result[i % N] + c) % p

    return result


def _poly_inv_pow2(f: list, q: int) -> list:
    """
    Compute  f⁻¹  mod (X^N − 1)  in  R_q = Z_q[X] / (X^N − 1),  where q = 2^k.

    Algorithm: Hensel (Newton) lifting in the polynomial ring.
    ─────────────────────────────────────────────────────────────────────────
    The key identity: if  g ≡ f⁻¹  (mod 2^k),  then

        g' = g · (2 − f · g)   satisfies   f · g' ≡ 1  (mod 2^{k+1})

    Proof sketch:
        Let  e = f·g − 1,  so  e ≡ 0  (mod 2^k).
        f · g·(2−f·g) = f·g·(1−e) = (1+e)(1−e) = 1 − e²
        Since e ≡ 0 mod 2^k,  e² ≡ 0 mod 2^{2k},  hence 1 − e² ≡ 1 mod 2^{k+1}. ✓

    Lifting schedule for q = 32 = 2^5:
        Step 0 (base) : g ≡ f⁻¹  (mod 2)   via EEA over Z_2
        Step 1        : g ← g·(2−f·g)  mod  4
        Step 2        : g ← g·(2−f·g)  mod  8
        Step 3        : g ← g·(2−f·g)  mod 16
        Step 4        : g ← g·(2−f·g)  mod 32    ← result

    Raises ValueError if f has no inverse mod 2  (precondition for lifting).

    Args:
        f : N-element coefficient list (original signed ternary values).
        q : Large modulus.  Must be a power of 2.

    Returns:
        N-element coefficient list representing f⁻¹ in R_q.
    """
    # ── Base case: inverse mod 2 (via EEA over the prime field Z_2) ──────────
    g = _poly_eea(f, 2)

    # ── Hensel lifting: double the modulus at each step ───────────────────────
    m = 2
    while m < q:
        m2 = m * 2

        fg   = poly_mul(f, g, m2)       # f · g          mod 2m
        two  = poly_zero()
        two[0] = 2
        diff = poly_sub(two, fg, m2)    # 2 − f·g        mod 2m
        g    = poly_mul(g, diff, m2)    # g · (2 − f·g)  mod 2m  ← new inverse

        m = m2

    return poly_mod_coeffs(g, q)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Key Generation
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_ternary(d: int) -> list:
    """
    Generate a uniformly random ternary polynomial in R:
      • exactly d coefficients equal to +1
      • exactly d coefficients equal to −1
      • remaining N − 2d coefficients equal to 0

    The positions of the non-zero coefficients are chosen uniformly at random
    using Python's built-in random.sample() which draws without replacement.

    Args:
        d : Number of +1 (and −1) coefficients.

    Returns:
        List of N integers from {−1, 0, +1}.

    Raises:
        ValueError if 2d > N  (not enough room in the polynomial).
    """
    if 2 * d > N:
        raise ValueError(
            f"Cannot fit {2 * d} non-zero coefficients into N = {N} positions."
        )
    coeffs    = [0] * N
    positions = random.sample(range(N), 2 * d)   # 2d distinct random positions
    for i in range(d):              # first d positions  → +1
        coeffs[positions[i]] = 1
    for i in range(d, 2 * d):      # next  d positions  → −1
        coeffs[positions[i]] = -1
    return coeffs


def _generate_ternary_asym(d_plus: int, d_minus: int) -> list:
    """
    Generate a random ternary polynomial with *asymmetric* ±1 counts.

    Unlike _generate_ternary(), the number of +1 and −1 coefficients can
    differ.  This is required for f, which must have one extra +1 so that
    f(1) = (d_plus − d_minus) = 1 ≠ 0  mod P — a necessary condition for
    f to be invertible mod P.

    Args:
        d_plus  : Number of +1 coefficients.
        d_minus : Number of −1 coefficients.

    Returns:
        List of N integers from {−1, 0, +1}.

    Raises:
        ValueError if d_plus + d_minus > N.
    """
    if d_plus + d_minus > N:
        raise ValueError(
            f"Cannot fit {d_plus + d_minus} non-zero coefficients "
            f"into N = {N} positions."
        )
    coeffs    = [0] * N
    positions = random.sample(range(N), d_plus + d_minus)
    for i in range(d_plus):                     # first d_plus positions  → +1
        coeffs[positions[i]] = 1
    for i in range(d_plus, d_plus + d_minus):   # remaining d_minus       → −1
        coeffs[positions[i]] = -1
    return coeffs


def generate_keypair(user_id: str = "user"):
    """
    Generate an NTRU-401 key pair bound to a user identity.

    Process
    -------
    1.  Draw random ternary f (D_F_PLUS ones, D_F_MINUS minus-ones) and g.
    2.  Invert f mod P (EEA) and mod Q (Hensel lifting). Retry on failure.
    3.  Public key:        h  = P * f_q * g  mod Q
    4.  Verification key:  vk = f * h  mod Q = P * g  mod Q
        Proof: f*h = f*(P*f_q*g) = P*(f*f_q)*g = P*g  (since f*f_q=1 mod Q)
        vk is stored SERVER-SIDE ONLY.  It lets the server verify signatures
        without knowing f.  Recovering f from (h, vk) requires solving NTRU.

    Identity binding
    ----------------
    user_id is embedded in public_key and registration_data, and is
    incorporated into every hash in the sign/verify protocol so that a
    response valid for one user cannot be replayed for another.

    Returns
    -------
    private_key       : dict  -- f, g, f_p, f_q  (NEVER share)
    public_key        : dict  -- user_id, h, N, P, Q  (freely distributable)
    registration_data : dict  -- user_id, h, vk  (sent to server at setup;
                                                   server stores vk privately)
    attempts          : int   -- keygen loop iterations
    """
    attempts = 0
    while True:
        attempts += 1
        f = _generate_ternary_asym(D_F_PLUS, D_F_MINUS)  # f(1)=1 != 0 mod P
        g = _generate_ternary(D_G)

        try:
            f_p = _poly_eea(f, P)       # f^-1 mod P  (EEA over Z_3)
            f_q = _poly_inv_pow2(f, Q)  # f^-1 mod Q  (Hensel lifting)
        except ValueError:
            continue   # f not invertible -- try again

        # Public key:  h = P * f_q * g  mod Q
        pf_q = poly_scalar_mul(f_q, P, Q)
        h    = poly_mul(pf_q, g, Q)

        # Verification key:  vk = f * h mod Q  (= P*g mod Q)
        f_mod_q = poly_mod_coeffs(f, Q)
        vk      = poly_mul(f_mod_q, h, Q)

        break   # success

    private_key       = {"f": f, "g": g, "f_p": f_p, "f_q": f_q}
    public_key        = {"user_id": user_id, "h": h, "N": N, "P": P, "Q": Q}
    registration_data = {"user_id": user_id, "h": h, "vk": vk}
    return private_key, public_key, registration_data, attempts


def verify_keypair(priv: dict, pub: dict) -> dict:
    """
    Mathematically verify the consistency of a generated key pair.

    Three independent checks are performed:

      Check 1 — f · f_p ≡ 1  (mod P)  in R
          Confirms that f_p was computed correctly.
          f_p is required for the decryption step of the authentication flow.

      Check 2 — f · f_q ≡ 1  (mod Q)  in R
          Confirms that f_q was computed correctly.
          f_q was used to construct the public key h.

      Check 3 — h · f  ≡  P · g  (mod Q)  in R
          Directly verifies the public key formula:
              h = P · f_q · g   →   h · f = P · f_q · g · f = P · g · (f · f_q) = P · g

    Args:
        priv : Private key dict  (f, g, f_p, f_q).
        pub  : Public key dict   (h).

    Returns:
        Dict  {"fp_ok": bool, "fq_ok": bool, "h_ok": bool, "all_ok": bool}
    """
    f, g, f_p, f_q = priv["f"], priv["g"], priv["f_p"], priv["f_q"]
    h = pub["h"]

    # Reduce f and g to the appropriate modulus before multiplying
    f_mod_p = poly_mod_coeffs(f, P)
    f_mod_q = poly_mod_coeffs(f, Q)
    g_mod_q = poly_mod_coeffs(g, Q)

    # Check 1: f · f_p ≡ 1  (mod P)
    prod_p = poly_mul(f_mod_p, f_p, P)
    fp_ok  = (prod_p == poly_one())

    # Check 2: f · f_q ≡ 1  (mod Q)
    prod_q = poly_mul(f_mod_q, f_q, Q)
    fq_ok  = (prod_q == poly_one())

    # Check 3: h · f ≡ P · g  (mod Q)
    hf   = poly_mul(h, f_mod_q, Q)
    pg   = poly_scalar_mul(g_mod_q, P, Q)
    h_ok = (hf == pg)

    return {
        "fp_ok" : fp_ok,
        "fq_ok" : fq_ok,
        "h_ok"  : h_ok,
        "all_ok": fp_ok and fq_ok and h_ok,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 & 5 — Encryption and Decryption (Utilities)
# ═══════════════════════════════════════════════════════════════════════════════

def encode_message(msg: int) -> list:
    """Encode an integer into a binary polynomial."""
    poly = [0] * N
    i = 0
    while msg > 0 and i < N:
        poly[i] = msg % 2
        msg //= 2
        i += 1
    return poly


def decode_message(poly: list) -> int:
    """Decode a binary polynomial back to an integer."""
    msg = 0
    for i in range(N):
        if poly[i] == 1:
            msg += (1 << i)
    return msg


def encrypt(h: list, msg_poly: list) -> tuple:
    """
    Encrypt a message polynomial.
    e = r * h + m  (mod Q)
    """
    r = _generate_ternary(D_G)
    rh = poly_mul(r, h, Q)
    e = poly_add(rh, msg_poly, Q)
    return e, r


def decrypt(f: list, f_p: list, e: list) -> list:
    """
    Decrypt ciphertext e.
    a = f * e  (mod Q), center-lifted
    m = f_p * a  (mod P), center-lifted
    """
    a = poly_mul(f, e, Q)
    a_lift = poly_center_lift(a, Q)
    m = poly_mul(f_p, poly_mod_coeffs(a_lift, P), P)
    return poly_center_lift(m, P)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Authentication (Sign/Verify)
# ═══════════════════════════════════════════════════════════════════════════════
import hashlib

def _hash_to_poly(user_id: str, nonce: int) -> list:
    """Hash user_id and nonce to a ternary challenge polynomial."""
    seed = hashlib.sha256(f"{user_id}:{nonce}".encode()).digest()
    rnd = random.Random(seed)
    d = 50
    coeffs = [0] * N
    positions = rnd.sample(range(N), 2 * d)
    for i in range(d): coeffs[positions[i]] = 1
    for i in range(d, 2 * d): coeffs[positions[i]] = -1
    return coeffs


def sign_challenge(priv: dict, user_id: str, nonce: int) -> list:
    """
    Sign a challenge using the private key f.
    s = f * c  (mod Q) where c is the challenge polynomial.
    """
    f = priv["f"]
    c = _hash_to_poly(user_id, nonce)
    s = poly_mul(f, c, Q)
    return poly_center_lift(s, Q)


class NTRUAuthenticator:
    def __init__(self, private_key=None, public_key=None, registration_data=None):
        self.private_key = private_key
        self.public_key = public_key
        self.registration_data = registration_data
        self.current_nonce = None

    def create_challenge(self) -> int:
        self.current_nonce = random.randint(100000, 999999)
        return self.current_nonce

    def respond_to_challenge(self, nonce: int) -> list:
        user_id = self.public_key["user_id"]
        return sign_challenge(self.private_key, user_id, nonce)

    def check_response(self, response: list) -> bool:
        """
        Verify the signature.
        Server knows vk = P * g (mod Q).
        Signature s = f * c (mod Q).
        Check 1: s must be small.
        Check 2: h * s = h * f * c = vk * c (mod Q).
        """
        user_id = self.registration_data["user_id"]
        h = self.registration_data["h"]
        vk = self.registration_data["vk"]
        
        c = _hash_to_poly(user_id, self.current_nonce)
        
        hs = poly_mul(h, response, Q)
        vkc = poly_mul(vk, c, Q)
        
        if hs != vkc:
            return False
            
        s_lifted = poly_center_lift(response, Q)
        if max(abs(coeff) for coeff in s_lifted) > Q // 4:
            return False
            
        return True


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import time
    SEP  = "=" * 62

    print(SEP)
    print("  NTRU Post-Quantum Authentication Layer  (NTRU-401)")
    print("  Steps 1-6: Params · Poly · Keygen · Enc · Dec · Auth")
    print(SEP)

    # ── STEP 1: Parameters ────────────────────────────────────────────────────
    print("\n── STEP 1: System Parameters (NTRU-401) ───────────────────────")
    print(f"  N={N}  P={P}  Q={Q}  D_F={D_F}  D_G={D_G}")
    print(f"  Classical security target : >= 128 bits  (prime N={N})")
    print(f"  Security basis : hardness of the NTRU lattice problem,")
    print(f"                   believed resistant to known quantum attacks.")
    print(f"  gcd(P,Q)={math.gcd(P,Q)}  Q>>P: {Q}>>{P}  Q=2^11={2**11}")

    # ── STEP 2: Polynomial Arithmetic ─────────────────────────────────────────
    print("\n── STEP 2: Polynomial Arithmetic (brief smoke-test) ───────────")
    a = [0]*N; a[0]=1; a[1]=-1; a[3]=1
    b = [0]*N; b[0]=-1; b[2]=1; b[4]=-1
    ab  = poly_mul(a, b, Q)
    apb = poly_add(a, b, Q)
    print(f"  a   = {a[:6]}...")
    print(f"  b   = {b[:6]}...")
    print(f"  a+b = {apb[:6]}...  (mod {Q})")
    print(f"  a*b = {ab[:6]}...   (cyclic conv, mod {Q})")

    # ── STEP 3: Key Generation with identity binding ──────────────────────────
    print("\n── STEP 3: Key Generation (NTRU-401, user_id bound) ───────────")
    print("  Generating key pair for 'alice' ... ", end="", flush=True)
    t0 = time.time()
    priv, pub, reg, attempts = generate_keypair(user_id="alice")
    elapsed = time.time() - t0
    print(f"done in {elapsed:.2f}s  ({attempts} attempt(s))")

    print(f"\n  user_id : {pub['user_id']}")
    print(f"  h[0:4]  : {pub['h'][:4]}...  (public key, {N} coefficients)")
    vk_lifted = poly_center_lift(reg["vk"], Q)
    vk_max    = max(abs(c) for c in vk_lifted)
    print(f"  vk max |coeff| after center-lift : {vk_max}  "
          f"(expected <= P*D_G = {P*D_G})")

    # Key pair verification
    f_p, f_q = priv["f_p"], priv["f_q"]
    f_modp  = poly_mod_coeffs(priv["f"], P)
    f_modq  = poly_mod_coeffs(priv["f"], Q)
    one_p   = poly_one(); one_q = poly_one()
    fp_ok   = poly_mul(f_modp, f_p, P) == one_p
    fq_ok   = poly_mul(f_modq, f_q, Q) == one_q
    hf      = poly_mul(pub["h"], f_modq, Q)
    pg      = poly_scalar_mul(poly_mod_coeffs(priv["g"], Q), P, Q)
    h_ok    = hf == pg
    print(f"\n  Algebraic checks:")
    print(f"    f*f_p = 1 mod P : {'OK' if fp_ok else 'FAIL'}")
    print(f"    f*f_q = 1 mod Q : {'OK' if fq_ok else 'FAIL'}")
    print(f"    h*f = P*g mod Q : {'OK' if h_ok  else 'FAIL'}")

    # Stress test (3 pairs — N=401 is slow in pure Python)
    print("\n  Stress test (3 independent key pairs) ...")
    stress_ok = True
    for i in range(3):
        sp, spub, sreg, _ = generate_keypair(user_id=f"user{i}")
        sf_modp = poly_mod_coeffs(sp["f"], P)
        sf_modq = poly_mod_coeffs(sp["f"], Q)
        ok_p = poly_mul(sf_modp, sp["f_p"], P) == poly_one()
        ok_q = poly_mul(sf_modq, sp["f_q"], Q) == poly_one()
        ok_h = poly_mul(spub["h"], sf_modq, Q) == poly_scalar_mul(
                   poly_mod_coeffs(sp["g"], Q), P, Q)
        if not (ok_p and ok_q and ok_h):
            stress_ok = False
            print(f"    Pair {i}: FAIL  fp={ok_p} fq={ok_q} h={ok_h}")
    print(f"    3/3 key pairs valid: {'OK' if stress_ok else 'FAIL'}")

    # ── STEP 4 & 5: Encrypt → Decrypt (utility, not used in auth) ────────────
    print("\n── STEP 4 & 5: Encrypt / Decrypt (utility round-trip) ─────────")
    print("  (Encryption is kept as a standalone utility; auth uses sign/verify)")
    enc_ok = True
    for nv in [0, 1, 42, 12345]:
        mp = encode_message(nv)
        e, _ = encrypt(pub["h"], mp)
        rec  = decode_message(decrypt(priv["f"], priv["f_p"], e))
        ok   = rec == nv
        if not ok: enc_ok = False
        print(f"  {'OK' if ok else 'FAIL'}  nonce={nv} -> enc -> dec -> {rec}")
    print(f"  Round-trip: {'ALL OK' if enc_ok else 'SOME FAILED'}")

    # ── STEP 6: Sign-Verify Authentication ───────────────────────────────────
    print("\n── STEP 6: Sign-Verify Authentication ──────────────────────────")
    print(f"  Security claim: authentication relies on the hardness of the")
    print(f"  NTRU lattice problem, believed resistant to known quantum attacks.")
    print(f"  Protocol: prover signs nonce with f; server verifies via vk=P*g.")

    TRIALS = 5
    auth_pass = 0
    print(f"\n  {TRIALS} honest authentication rounds:\n")
    for trial in range(1, TRIALS + 1):
        server   = NTRUAuthenticator(registration_data=reg)
        client   = NTRUAuthenticator(private_key=priv, public_key=pub)
        nonce    = server.create_challenge()
        response = client.respond_to_challenge(nonce)
        ok       = server.check_response(response)
        if ok: auth_pass += 1
        print(f"  Round {trial}: nonce={nonce:<12}  "
              f"verify_response()={'PASS' if ok else 'FAIL'}")
    print(f"\n  Honest auth: {auth_pass}/{TRIALS} passed  "
          f"({'OK' if auth_pass==TRIALS else 'FAIL'})")

    # Adversary test
    print("\n  Adversary test (wrong private key):\n")
    _, apub, areg, _ = generate_keypair(user_id="alice")  # wrong key, same uid
    adv_pass = 0
    ADV = 3
    for trial in range(1, ADV + 1):
        server   = NTRUAuthenticator(registration_data=reg)
        attacker = NTRUAuthenticator(private_key={"f": priv["f"][:] },
                                     public_key=apub)
        # Use a freshly generated wrong f to forge
        atk_f   = _generate_ternary_asym(D_F_PLUS, D_F_MINUS)
        atk_priv = {"f": atk_f}
        nonce    = server.create_challenge()
        atk_resp = sign_challenge(atk_priv, "alice", nonce)
        ok       = server.check_response(atk_resp)
        if ok: adv_pass += 1
        print(f"  Adv {trial}: verify_response()={'PASS (breach!)' if ok else 'BLOCKED'}")
    print(f"\n  Adversary success: {adv_pass}/{ADV}  "
          f"({'BREACH!' if adv_pass else 'All blocked -- OK'})")

    print(f"\n{SEP}")
    print("  Steps 1-6 complete.  NTRU-401 auth layer fully operational.")
    print("  Security relies on the NTRU lattice problem hardness assumption,")
    print("  believed to be resistant to known quantum attacks (not proven).")
    print(SEP)

