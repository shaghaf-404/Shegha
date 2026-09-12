 <img width="693" height="247" alt="image" src="https://github.com/user-attachments/assets/5f4c602c-76cf-41a5-a990-403c0dd9ad3b" />

 



# Shegha — Hybrid Cryptography CLI

> Secure, post-quantum communication over standard TCP — ElGamal key exchange · NTRU authentication · RC5 + Feistel encryption · CA trust model · Silent Trust branch liveness

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## What is Shegha?

Shegha is a command-line cryptography toolkit that establishes **end-to-end encrypted sessions** between a server, clients, and branch servers using a layered, hybrid security model:

<img width="691" height="349" alt="image" src="https://github.com/user-attachments/assets/637d84fc-0f18-43d7-986e-1c64f3716696" />


| Layer | Algorithm | Purpose |
|---|---|---|
| Key Exchange | ElGamal (1024-bit safe prime) | Asymmetric session-key establishment |
| Authentication | NTRU (post-quantum) | Identity verification, quantum-resistant |
| Symmetric Cipher | RC5 + Feistel | High-speed message encryption on the wire |
| Trust Anchor | Custom CA (ElGamal-signed) | Certificate issuance and verification |
| Branch Liveness | Silent Trust (BFD-inspired) | Passive heartbeat authentication between branches |

All cryptographic primitives are implemented from scratch in pure Python — **no third-party crypto libraries required**.

---

## Quick Install

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/shegha.git
cd shegha

# 2. Install (registers the `shegha` command system-wide)
pip install -e .

# 3. Run
shegha
```

After step 2, the `shegha` command is available in any terminal window.

---

## Usage

```
$ shegha <mode>
```

| Mode | Description |
|---|---|
| `shegha server` | Start the main secure server (ElGamal + CA + Feistel) |
| `shegha client` | Start a client session (NTRU auth + RC5 stream) |
| `shegha branch-server` | Start a branch server (ElGamal + CA + Feistel) |

### Examples

```bash
# Terminal 1 — start the server
shegha server

# Terminal 2 — connect a client
shegha client

# Terminal 3 — connect a branch server
shegha branch-server
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Shegha Network                    │
│                                                     │
│   ┌──────────┐    ElGamal     ┌──────────────────┐  │
│   │  Client  │◄──key exchange─►│  Main Server     │  │
│   │  (NTRU   │                 │  (CA · Feistel)  │  │
│   │   auth)  │◄── RC5 stream ─►│                  │  │
│   └──────────┘                 └─────────┬────────┘  │
│                                          │            │
│                               Silent     │ Trust      │
│                               heartbeat  │            │
│                                          ▼            │
│                               ┌──────────────────┐   │
│                               │  Branch Server   │   │
│                               │  (ElGamal + CA)  │   │
│                               └──────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Handshake flow

```
CLIENT                          SERVER
  │── CLIENT_HELLO ──────────────► │
  │◄── SERVER_HELLO (ElGamal pk) ──│
  │── KEY_EXCHANGE (encrypted sk) ►│
  │── CERT_REQUEST ────────────── ►│
  │◄── CERT_VERIFY (NTRU sig) ─────│
  │◄══════ RC5 session active ══════│
```

---

## Modules

```
shegha/
├── shegha_cli.py           # CLI entry point  →  shegha <mode>
└── crypto/
    ├── ca.py               # Certificate Authority — ElGamal-signed certs
    ├── silent_trust.py     # Branch liveness — passive heartbeat auth
    ├── benchmark.py        # Crypto performance benchmarks
    ├── asymmetric/
    │   └── elgamal.py      # ElGamal encryption + digital signatures
    ├── pqc/
    │   └── NTRU.py         # NTRU post-quantum key gen + auth
    └── symmetric/
        ├── chat.py         # Full secure chat session (server/client/branch)
        ├── rc5.py          # RC5 block cipher
        └── feistel.py      # Feistel network cipher
```

---

## Cryptographic Highlights

- **ElGamal** — 1024-bit IETF RFC 3526 safe prime, used for key exchange and CA signatures
- **NTRU** — Post-quantum lattice-based cryptosystem for identity authentication
- **RC5** — Parameterised block cipher for symmetric session encryption
- **Feistel cipher** — Custom Feistel network as an additional encryption layer
- **Silent Trust** — BFD/RFC 5880-inspired passive liveness: silence = untrusted
- **Custom CA** — Certificate issuance and verification without external PKI

---

## Requirements

- Python **3.10 or later**
- No external packages — everything uses the Python standard library

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built as part of a Computer & Network Security curriculum project.*
