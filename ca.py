import hashlib
import json
import uuid
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from asymmetric.elgamal import (
    ElGamalKeyPair,
    _P_1024, _G_1024,
    _mod_exp, _mod_inverse, _gcd, _secure_randrange,
    _validate_public_key
)

# -----------------------------------------------------------------------------
# Static CA Trust Anchor
# -----------------------------------------------------------------------------
CA_P = _P_1024
CA_G = _G_1024
CA_X = 21829592144289763508048346042550785932871116034298561331035165684727928862062809715815785093564320889638758792271471732543735398888104080470598213812089965038779354096195313314431616191004241716768607110330406087816459340645162043582311648480905937625489395826213602151856731481651506114328440776724509129713994608283412760965753312950209954894419769691314031851288511467502808190835153526698551308226736946040911712354047442462145628133073629992149263302243826096361616962068766980714284792007137402997498239759531848748981152429905225391469153664560750489201086316943119400088227751747171102202599146333192419589414
CA_Y = 10738467799382345483920536873749425597337648283811435205249019639377273052909435990490272689797619576260827076619639132473128689547109008734568655308042189373380003648233049223960323976632475145635458613009940747301108111654880375646182977945547232094592621457596197862046062168171083987071354489343084085045163918313104689275693602246233329738938356579522300483984462579588581044283315985573096991869034600122290703057941342343456955477944773195484834589203025447419573958748414694343076051918214602261270425383985586818476544295565881417265875827173215814643590275657030822657152122596919570222939908079842634029461

CA_PUBLIC_KEY = {"p": CA_P, "g": CA_G, "y": CA_Y}
CA_KEYPAIR = ElGamalKeyPair(p=CA_P, g=CA_G, x=CA_X, y=CA_Y)

# -----------------------------------------------------------------------------
# ElGamal Digital Signatures
# -----------------------------------------------------------------------------

def _hash_to_int(data: bytes, p: int) -> int:
    """Hash data with SHA-256 and return an integer modulo (p-1)."""
    h = hashlib.sha256(data).digest()
    m = int.from_bytes(h, byteorder='big')
    # According to ElGamal signature schema, m should be in [0, p-2]
    # We'll map it to mod (p-1)
    return m % (p - 1)

def sign_data(data_bytes: bytes, keypair: ElGamalKeyPair) -> tuple:
    """
    Sign data_bytes using ElGamal signature scheme.
    Returns (r, s)
    """
    p = keypair.p
    g = keypair.g
    x = keypair.x
    
    m = _hash_to_int(data_bytes, p)
    
    p_minus_1 = p - 1
    
    # Choose random k such that 1 < k < p-1 and gcd(k, p-1) == 1
    for _ in range(1000):
        k = _secure_randrange(2, p_minus_1)
        if _gcd(k, p_minus_1) == 1:
            break
    else:
        raise RuntimeError("Failed to find ephemeral k for signing.")
        
    r = _mod_exp(g, k, p)
    k_inv = _mod_inverse(k, p_minus_1)
    
    # s = (m - x * r) * k^-1 mod (p - 1)
    s = ((m - x * r) * k_inv) % p_minus_1
    
    return r, s

def verify_signature(data_bytes: bytes, signature: tuple, public_key: dict) -> bool:
    """
    Verify ElGamal signature (r, s) for data_bytes.
    """
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]
    r, s = signature
    
    if not (1 < r < p) or not (0 <= s < p - 1):
        return False
        
    m = _hash_to_int(data_bytes, p)
    
    # Check if (y^r * r^s) mod p == g^m mod p
    v1 = (_mod_exp(y, r, p) * _mod_exp(r, s, p)) % p
    v2 = _mod_exp(g, m, p)
    
    return v1 == v2

# -----------------------------------------------------------------------------
# Certificate Authority
# -----------------------------------------------------------------------------

class CertificateAuthority:
    """
    CA that issues and verifies certificates.
    """
    def __init__(self):
        self.keypair = CA_KEYPAIR
        self.public_key = CA_PUBLIC_KEY

    def issue_certificate(self, subject_name: str, subject_public_key: dict) -> dict:
        """
        Create and sign a certificate for a given subject.
        """
        cert_data = {
            "subject": subject_name,
            "public_key": subject_public_key,
            "issuer": "CA",
            "serial": str(uuid.uuid4())
        }
        
        # Serialize deterministically to hash
        data_to_sign = json.dumps(cert_data, sort_keys=True).encode('utf-8')
        r, s = sign_data(data_to_sign, self.keypair)
        
        return {
            "data": cert_data,
            "signature": {"r": r, "s": s}
        }

def verify_certificate(cert: dict, ca_public_key: dict) -> bool:
    """
    Verify that the certificate was signed by the CA.
    """
    if "data" not in cert or "signature" not in cert:
        return False
        
    data = cert["data"]
    if data.get("issuer") != "CA":
        return False
        
    sig_dict = cert["signature"]
    if "r" not in sig_dict or "s" not in sig_dict:
        return False
        
    signature = (sig_dict["r"], sig_dict["s"])
    data_to_verify = json.dumps(data, sort_keys=True).encode('utf-8')
    
    return verify_signature(data_to_verify, signature, ca_public_key)
