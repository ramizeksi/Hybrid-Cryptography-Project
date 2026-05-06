# Hybrid KEM Secure File Transfer System

## ML-KEM-768 (Kyber) + X25519 + AES-256-GCM

A hybrid post-quantum cryptographic file transfer application built with Python and PyQt6, implementing defense-in-depth by combining classical and post-quantum key exchange mechanisms.

---

## Architecture

```
Alice (Client/Sender)                    Bob (Server/Receiver)
─────────────────────                    ─────────────────────
                                         1. Generate X25519 keypair
                                         2. Generate ML-KEM-768 keypair
                                    ←──  3. Send public keys

4. Generate X25519 keypair
5. Compute classical secret (ECDH)
6. Encapsulate PQ secret (ML-KEM)
7. Derive hybrid key:
   HKDF-SHA256(classical ∥ PQ)
8. Encrypt file (AES-256-GCM)
9. Send X25519 pub + ciphertext  ──→
10. Send encrypted file          ──→
                                         11. Compute classical secret
                                         12. Decapsulate PQ secret
                                         13. Derive same hybrid key
                                         14. Decrypt + verify GCM tag
                                         15. Save file
```

## Installation

### Prerequisites
- Python 3.10+
- liboqs system library (for ML-KEM-768)

### Install liboqs (system library)

**Ubuntu/Debian:**
```bash
sudo apt install cmake gcc ninja-build libssl-dev
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install
sudo ldconfig
```

**macOS (Homebrew):**
```bash
brew install cmake ninja openssl
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install
```

**Windows:**
See https://github.com/open-quantum-safe/liboqs#windows

### Install Python dependencies
```bash
pip install -r requirements.txt
```

## Usage

```bash
python main_ui.py
```

### Running a File Transfer

1. **Start Server (Bob):**
   - Set IP to `127.0.0.1` (localhost) and Port to `9876`
   - Choose a save directory
   - Click "Start Server"

2. **Send File (Alice):**
   - In a second instance (or same window after server is listening)
   - Set same IP and Port
   - Click "Browse File" and select a file
   - Click "Encrypt & Send File"

3. **Observe the log** for cryptographic steps (key generation, encapsulation, HKDF derivation, AES-GCM encryption/decryption)

### Test Scenarios

Switch to the **Test Scenarios & Attacks** tab:

| Scenario | Toggle | Expected Result |
|----------|--------|-----------------|
| 1. Core Functionality | (none) | File transfers and decrypts successfully |
| 2. Large File (1GB) | (none) | Chunk-based AES-GCM handles without OOM |
| 3. Ciphertext Tampering | ☑ Simulate Ciphertext Tampering | Server: "Integrity Check Failed" |
| 4. Broken PQ Algorithm | ☑ Simulate Broken PQ Algorithm | Server: Decryption fails (key mismatch) |
| 5. Benchmark | Click "Run Benchmark" | Average latencies for X25519 and ML-KEM |
| 6. Replay Attack | ☑ Simulate Replay Attack | Server: Decryption fails (ephemeral key mismatch) |

## Project Structure

```
hybrid_kem_project/
├── crypto_engine.py   # Core cryptographic operations (KEM, HKDF, AES-GCM)
├── network_layer.py   # TCP server/client workers (QThread-based)
├── main_ui.py         # PyQt6 GUI application (entry point)
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

## Cryptographic Details

- **Classical KEM:** X25519 (Curve25519 ECDH) — 32-byte shared secret
- **Post-Quantum KEM:** ML-KEM-768 (NIST FIPS 203, formerly Kyber768) — 32-byte shared secret
- **Key Derivation:** HKDF-SHA256(ikm = classical_secret ∥ pq_secret, salt=None, info=b'Hybrid-KEM-v1')
- **Symmetric Encryption:** AES-256-GCM with 12-byte nonce, chunk-based (1MB chunks)
- **Integrity:** GCM authentication tag (128-bit) per chunk

## Security Model

The hybrid approach provides defense-in-depth:
- If X25519 is broken (quantum computer): ML-KEM-768 still protects the key
- If ML-KEM-768 is broken (classical attack): X25519 still protects the key
- An attacker must break BOTH algorithms to recover the hybrid key

## License

Academic research project — Dokuz Eylül University, Computer Engineering
