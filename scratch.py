import random
import math
import hashlib

N   = 401   
P   =   3   
Q   = 2048  
D_F       = 133
D_F_PLUS  = D_F + 1   
D_F_MINUS = D_F       
D_G       = 133       

def poly_zero() -> list:
    return [0] * N
def poly_mod_coeffs(f: list, m: int) -> list:
    return [c % m for c in f]
def poly_center_lift(f: list, m: int) -> list:
    half = m // 2
    return [c - m if c > half else c for c in (x % m for x in f)]
def poly_add(f: list, g: list, m: int) -> list:
    return [(f[i] + g[i]) % m for i in range(N)]
def poly_mul(f: list, g: list, m: int) -> list:
    h = [0] * N
    for i in range(N):
        if f[i] == 0: continue
        for j in range(N):
            h[(i + j) % N] = (h[(i + j) % N] + f[i] * g[j]) % m
    return h
def _generate_ternary(d: int) -> list:
    coeffs = [0] * N
    positions = random.sample(range(N), 2 * d)
    for i in range(d): coeffs[positions[i]] = 1
    for i in range(d, 2 * d): coeffs[positions[i]] = -1
    return coeffs

# ═══════════════════════════════════════════════════════════════════════════════
# Missing functions:
def encode_message(msg: int) -> list:
    poly = [0] * N
    i = 0
    while msg > 0 and i < N:
        poly[i] = msg % 2
        msg //= 2
        i += 1
    return poly

def decode_message(poly: list) -> int:
    msg = 0
    for i in range(N):
        if poly[i] == 1:
            msg += (1 << i)
    return msg

def encrypt(h: list, msg_poly: list) -> tuple:
    r = _generate_ternary(D_G)
    rh = poly_mul(r, h, Q)
    e = poly_add(rh, msg_poly, Q)
    return e, r

def decrypt(f: list, f_p: list, e: list) -> list:
    a = poly_mul(f, e, Q)
    a_lift = poly_center_lift(a, Q)
    m = poly_mul(f_p, poly_mod_coeffs(a_lift, P), P)
    return poly_center_lift(m, P)

def _hash_to_poly(user_id: str, nonce: int) -> list:
    seed = hashlib.sha256(f"{user_id}:{nonce}".encode()).digest()
    rnd = random.Random(seed)
    d = 50
    coeffs = [0] * N
    positions = rnd.sample(range(N), 2 * d)
    for i in range(d): coeffs[positions[i]] = 1
    for i in range(d, 2 * d): coeffs[positions[i]] = -1
    return coeffs

def sign_challenge(priv: dict, user_id: str, nonce: int) -> list:
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
        user_id = self.registration_data["user_id"]
        h = self.registration_data["h"]
        vk = self.registration_data["vk"]
        c = _hash_to_poly(user_id, self.current_nonce)
        hs = poly_mul(h, response, Q)
        vkc = poly_mul(vk, c, Q)
        if hs != vkc: return False
        s_lifted = poly_center_lift(response, Q)
        if max(abs(coeff) for coeff in s_lifted) > Q // 4: return False
        return True

print("Defined all.")
