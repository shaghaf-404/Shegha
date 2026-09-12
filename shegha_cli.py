import sys
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ─────────────────────────────────────────────
#  Terminal colour helpers (no external deps)
# ─────────────────────────────────────────────
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


def _banner():
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


def _handshake_log(role):
    """Simulate the ElGamal handshake visual log."""
    _section("ElGamal handshake")
    steps = [
        ("HS", "CLIENT_HELLO sent",         "initiating key exchange"),
        ("HS", "SERVER_HELLO received",      "ElGamal public params ← server"),
        ("HS", "KEY_EXCHANGE",               "encrypting session key with Gₚ"),
        ("HS", "CERT_REQUEST sent",          "requesting CA certificate"),
        ("HS", "CERT_VERIFY",               "NTRU signature verified ✔"),
        ("HS", "SESSION_ESTABLISHED",       "RC5 session key active"),
    ] if role == "client" else [
        ("HS", "CLIENT_HELLO received",     "new peer detected"),
        ("HS", "SERVER_HELLO sent",         "ElGamal public params → client"),
        ("HS", "KEY_EXCHANGE received",     "decrypting with private key xₐ"),
        ("HS", "CERT issued",               "signing with CA ElGamal key"),
        ("HS", "CERT_VERIFY sent",          "NTRU proof attached"),
        ("HS", "SESSION_ESTABLISHED",       "Feistel layer armed"),
    ]
    if role == "branch-server":
        """
        Client -> Server messages (what the CLIENT sends to the SERVER)

        This is the *second* half of the 2-step flow.

        The client already received the server's public key in "SERVER_HELLO",
        now it replies with:

          1) "SESSION_KEY_CT": the encrypted session key (ElGamal encryption)
          2) "CLIENT_CERT": the CA-signed certificate for the branch
        """
        steps = [
            ("HS", "CLIENT_HELLO sent",         "initiating key exchange"),
            ("HS", "SERVER_HELLO received",     "ElGamal public params ← server"),
            ("KEY_EXCHANGE", "encrypting session key with Gₚ"),
            ("HS", "SESSION_KEY_CT sent",       "encrypted session key ← client"),
            ("HS", "CLIENT_CERT sent",        "CA-signed branch certificate"),
        ]
    
    for tag, event, detail in steps:
        time.sleep(0.12)
        print(f"  {C.G4}[{C.G2}{tag}{C.G4}]{C.RESET}  {C.W}{event:<30}{C.RESET}  {C.MUT}{detail}{C.RESET}")
    print()


def _usage():
    _banner()
    _section("usage")
    _tag("command", "shegha  <mode>")
    print()
    _tag("server ", "start the secure server  (ElGamal + CA + Feistel)", C.G2)
    _tag("client ", "start a client session   (NTRU auth + RC5 stream)",  C.G2)
    _tag("branch-server", "start a branch server   (ElGamal + CA + Feistel)",  C.G2)
    print()
    _section("examples")
    print(f"  {C.MUT}${C.RESET}  {C.G3}shegha server{C.RESET}")
    print(f"  {C.MUT}${C.RESET}  {C.G3}shegha client{C.RESET}")
    print(f"  {C.MUT}${C.RESET}  {C.G3}shegha branch-server{C.RESET}")
    print()
    _line()
    print()


def _boot_server():
    _banner()
    _section("starting server")
    _spinner("loading ElGamal key material …",  0.5)
    _spinner("generating CA certificate …",      0.4)
    _spinner("arming Feistel encryption layer …", 0.3)
    _spinner("binding socket …",                 0.3)
    print()
    _status("✔", "server ready", "waiting for connections", C.OK)
    _line()
    print()


def _boot_client():
    _banner()
    _section("starting client")
    _spinner("loading NTRU key pair …",           0.45)
    _spinner("resolving server address …",        0.3)
    _spinner("opening TCP channel …",             0.25)
    print()
    _handshake_log("client")
    _status("✔", "secure session active", "RC5 stream encryption on", C.OK)
    _line()
    print()

def _boot_branch_server():
    _banner()
    _section("starting branch server")
    _spinner("loading ElGamal key material …",  0.5)
    _spinner("generating CA certificate …",      0.4)
    _spinner("arming Feistel encryption layer …", 0.3)
    _spinner("binding socket …",                 0.3)
    print()
    _status("✔", "server ready", "waiting for connections", C.OK)
    _line()
    print()


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        _usage()
        return

    mode = sys.argv[1].lower()

    if mode == "server":
        _boot_server()
        try:
            from crypto.symmetric.chat import start_server
            start_server()
        except ImportError:
            print(f"  {C.WARN}⚠{C.RESET}  {C.W}crypto module not found — running in demo mode{C.RESET}")

    elif mode == "client":
        _boot_client()
        try:
            from crypto.symmetric.chat import start_client
            start_client()
        except ImportError:
            print(f"  {C.WARN}⚠{C.RESET}  {C.W}crypto module not found — running in demo mode{C.RESET}")
    elif mode == "branch-server":
        _boot_branch_server()
        try:
            from crypto.symmetric.chat import start_branch_server
            start_branch_server()
        except ImportError:
            print(f"  {C.WARN}⚠{C.RESET}  {C.W}crypto module not found — running in demo mode{C.RESET}")
    else:
        print(f"\n  {C.ERR}✘{C.RESET}  {C.W}unknown mode:{C.RESET} {C.ERR}{mode!r}{C.RESET}")
        print(f"  {C.MUT}valid options: server  |  client{C.RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()