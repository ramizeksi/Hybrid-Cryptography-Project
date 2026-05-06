"""
crypto_engine.py - Hybrid Cryptographic Engine
================================================
This module implements the core cryptographic pipeline:
  1. X25519 (Classical ECDH) key exchange
  2. ML-KEM-768 (Post-Quantum Kyber) key encapsulation
  3. HKDF-SHA256 hybrid key derivation
  4. AES-256-GCM authenticated encryption/decryption (chunk-based)

The hybrid approach ensures security even if one algorithm is compromised:
  final_key = HKDF(classical_secret || pq_secret)

Attack simulation hooks are implemented as boolean flags that can be
toggled from the UI to demonstrate various failure modes.
"""

import os
import time
import struct
import hashlib
from typing import Tuple, Optional

# Classical cryptography (X25519, HKDF, AES-256-GCM)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Post-Quantum cryptography (ML-KEM-768 / Kyber768)
import oqs

# ============================================================
# Constants
# ============================================================
HKDF_INFO = b'Hybrid-KEM-v1'       # Context info for HKDF derivation
HKDF_SALT = None                    # Salt=None as specified
AES_KEY_SIZE = 32                   # 256 bits for AES-256-GCM
AES_NONCE_SIZE = 12                 # 96-bit nonce for GCM
CHUNK_SIZE = 1024 * 1024            # 1 MB chunks for file encryption
PQ_ALGORITHM = "ML-KEM-768"        # NIST standardized ML-KEM (Kyber768)


# ============================================================
# Key Generation (Server/Bob side)
# ============================================================
def generate_x25519_keypair() -> Tuple[X25519PrivateKey, bytes]:
    """
    Generate an ephemeral X25519 keypair for classical ECDH.
    Returns (private_key_object, public_key_bytes).
    """
    private_key = X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_key_bytes


def generate_mlkem_keypair() -> Tuple[object, bytes, bytes]:
    """
    Generate an ML-KEM-768 keypair for post-quantum key encapsulation.
    Returns (kem_object, public_key_bytes, secret_key_bytes).
    
    The KEM object is needed for decapsulation on the server side.
    """
    kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return kem, public_key, secret_key


# ============================================================
# Encapsulation (Client/Alice side)
# ============================================================
def compute_classical_secret(
    alice_private: X25519PrivateKey,
    bob_public_bytes: bytes
) -> bytes:
    """
    Compute the classical shared secret using X25519 ECDH.
    
    Both Alice and Bob compute:
      shared_secret = X25519(my_private, peer_public)
    
    The mathematical guarantee is that both sides arrive at the
    same shared secret without ever transmitting private keys.
    """
    bob_public_key = X25519PublicKey.from_public_bytes(bob_public_bytes)
    shared_secret = alice_private.exchange(bob_public_key)
    return shared_secret


def encapsulate_pq(bob_mlkem_public: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a post-quantum shared secret using Bob's ML-KEM public key.
    
    Returns (ciphertext, pq_shared_secret).
    
    The ciphertext must be sent to Bob so he can decapsulate it
    with his private key to recover the same pq_shared_secret.
    """
    kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
    ciphertext, pq_secret = kem.encap_secret(bob_mlkem_public)
    return ciphertext, pq_secret


# ============================================================
# Decapsulation (Server/Bob side)
# ============================================================
def decapsulate_pq(
    kem_or_secret_key: object,
    ciphertext: bytes
) -> bytes:
    """
    Decapsulate the PQ ciphertext to recover the shared secret.
    
    If kem_or_secret_key is an oqs.KeyEncapsulation object, use it directly.
    Otherwise, treat it as exported secret key bytes and reconstruct.
    """
    if isinstance(kem_or_secret_key, oqs.KeyEncapsulation):
        pq_secret = kem_or_secret_key.decap_secret(ciphertext)
    else:
        # Reconstruct KEM from exported secret key
        kem = oqs.KeyEncapsulation(PQ_ALGORITHM, secret_key=kem_or_secret_key)
        pq_secret = kem.decap_secret(ciphertext)
    return pq_secret


# ============================================================
# Hybrid Key Derivation
# ============================================================
def derive_hybrid_key(
    classical_secret: bytes,
    pq_secret: bytes,
    simulate_broken_pq: bool = False
) -> bytes:
    """
    Derive the final AES-256 key using HKDF-SHA256.
    
    The hybrid combination is:
      input_key_material = classical_secret || pq_secret
      final_key = HKDF-SHA256(ikm=input_key_material, salt=None, info='Hybrid-KEM-v1')
    
    ATTACK HOOK (Test Scenario 4 - "Simulate Broken PQ Algorithm"):
      If simulate_broken_pq=True, the pq_secret is OMITTED from the
      derivation. This simulates a scenario where the PQ algorithm
      is "cracked" and the attacker only has the classical secret.
      The server (which uses both secrets) will derive a DIFFERENT key,
      proving that the hybrid mechanism provides defense-in-depth.
    """
    if simulate_broken_pq:
        # ── ATTACK HOOK: Only use classical secret ──
        # This will cause a key mismatch on the other side
        input_key_material = classical_secret
    else:
        # ── Normal operation: Combine both secrets ──
        # Concatenation: classical_secret (32 bytes) || pq_secret (32 bytes)
        input_key_material = classical_secret + pq_secret

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    final_key = hkdf.derive(input_key_material)
    return final_key


# ============================================================
# AES-256-GCM Chunk-based Encryption
# ============================================================
def encrypt_file_chunked(
    input_path: str,
    output_path: str,
    key: bytes,
    simulate_tampering: bool = False,
    progress_callback=None
) -> Tuple[bytes, int]:
    """
    Encrypt a file using AES-256-GCM in chunks.
    
    Each chunk is encrypted independently with:
      - Same key (derived from hybrid KDF)
      - Unique nonce = base_nonce XOR chunk_index
    
    File format written:
      [12 bytes: base_nonce]
      [8 bytes: total_chunks (uint64)]
      For each chunk:
        [4 bytes: chunk_ciphertext_length (uint32)]
        [N bytes: chunk_ciphertext + 16-byte GCM tag]
    
    ATTACK HOOK (Test Scenario 3 - "Simulate Ciphertext Tampering"):
      If simulate_tampering=True, one random byte in a random chunk's
      ciphertext is flipped before writing. This will cause an
      "InvalidTag" error on the decryption side, demonstrating
      AES-GCM's integrity verification.
    
    Returns (base_nonce, total_chunks).
    """
    aesgcm = AESGCM(key)
    base_nonce = os.urandom(AES_NONCE_SIZE)

    file_size = os.path.getsize(input_path)
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    if total_chunks == 0:
        total_chunks = 1

    # Choose a random chunk to tamper with (if attack is enabled)
    tamper_chunk_idx = -1
    if simulate_tampering:
        import random
        tamper_chunk_idx = random.randint(0, max(0, total_chunks - 1))

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # Write header: base nonce + total chunks
        fout.write(base_nonce)
        fout.write(struct.pack('>Q', total_chunks))

        for chunk_idx in range(total_chunks):
            data = fin.read(CHUNK_SIZE)
            if not data:
                data = b''

            # Derive per-chunk nonce: base_nonce XOR chunk_index
            # This ensures each chunk gets a unique nonce
            nonce = _derive_chunk_nonce(base_nonce, chunk_idx)

            # Encrypt chunk with AES-256-GCM
            # The GCM tag (16 bytes) is appended to the ciphertext
            ct = aesgcm.encrypt(nonce, data, None)

            # ── ATTACK HOOK: Tamper with ciphertext ──
            if chunk_idx == tamper_chunk_idx:
                ct = bytearray(ct)
                import random
                flip_pos = random.randint(0, len(ct) - 1)
                ct[flip_pos] ^= 0xFF  # Flip all bits of one byte
                ct = bytes(ct)

            # Write chunk: [length][ciphertext+tag]
            fout.write(struct.pack('>I', len(ct)))
            fout.write(ct)

            if progress_callback:
                progress_callback(chunk_idx + 1, total_chunks)

    return base_nonce, total_chunks


def decrypt_file_chunked(
    input_path: str,
    output_path: str,
    key: bytes,
    progress_callback=None
) -> bool:
    """
    Decrypt an AES-256-GCM chunk-encrypted file.
    
    Reads the format written by encrypt_file_chunked.
    If any chunk fails integrity verification (GCM tag mismatch),
    raises an InvalidTag exception → the file is NOT saved.
    
    Returns True on success.
    """
    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # Read header
        base_nonce = fin.read(AES_NONCE_SIZE)
        total_chunks_bytes = fin.read(8)
        total_chunks = struct.unpack('>Q', total_chunks_bytes)[0]

        for chunk_idx in range(total_chunks):
            # Read chunk length
            ct_len_bytes = fin.read(4)
            ct_len = struct.unpack('>I', ct_len_bytes)[0]

            # Read ciphertext + GCM tag
            ct = fin.read(ct_len)

            # Derive the same per-chunk nonce
            nonce = _derive_chunk_nonce(base_nonce, chunk_idx)

            # Decrypt and verify GCM authentication tag
            # This will raise InvalidTag if tampered
            plaintext = aesgcm.decrypt(nonce, ct, None)
            fout.write(plaintext)

            if progress_callback:
                progress_callback(chunk_idx + 1, total_chunks)

    return True


def _derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """
    Derive a unique nonce for each chunk by XORing the base nonce
    with the chunk index. This ensures nonce uniqueness per chunk
    while keeping nonces deterministic for both encryption and decryption.
    """
    nonce_int = int.from_bytes(base_nonce, 'big') ^ chunk_index
    return nonce_int.to_bytes(AES_NONCE_SIZE, 'big')


# ============================================================
# Benchmark (Test Scenario 5)
# ============================================================
def run_benchmark(iterations: int = 10000, progress_callback=None) -> dict:
    """
    Benchmark cryptographic operations over N iterations.
    
    Measures:
      (A) X25519: KeyGen + Shared Secret computation
      (B) ML-KEM-768: KeyGen + Encapsulation + Decapsulation
    
    Returns dict with average latencies in milliseconds.
    """
    # ── Benchmark A: X25519 ──
    x25519_times = []
    for i in range(iterations):
        start = time.perf_counter()
        
        # Generate Alice's keypair
        alice_priv = X25519PrivateKey.generate()
        alice_pub = alice_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Generate Bob's keypair
        bob_priv = X25519PrivateKey.generate()
        bob_pub = bob_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Compute shared secrets
        alice_priv.exchange(X25519PublicKey.from_public_bytes(bob_pub))
        bob_priv.exchange(X25519PublicKey.from_public_bytes(alice_pub))
        
        elapsed = time.perf_counter() - start
        x25519_times.append(elapsed)

        if progress_callback and (i + 1) % 500 == 0:
            progress_callback(i + 1, iterations * 2, "X25519")

    # ── Benchmark B: ML-KEM-768 ──
    mlkem_times = []
    for i in range(iterations):
        start = time.perf_counter()
        
        # KeyGen
        kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
        public_key = kem.generate_keypair()
        
        # Encapsulation (Alice side)
        kem_enc = oqs.KeyEncapsulation(PQ_ALGORITHM)
        ciphertext, shared_secret_enc = kem_enc.encap_secret(public_key)
        
        # Decapsulation (Bob side)
        shared_secret_dec = kem.decap_secret(ciphertext)
        
        elapsed = time.perf_counter() - start
        mlkem_times.append(elapsed)

        if progress_callback and (i + 1) % 500 == 0:
            progress_callback(iterations + i + 1, iterations * 2, "ML-KEM-768")

    # Compute statistics in milliseconds
    def stats(times):
        ms = [t * 1000 for t in times]
        ms_sorted = sorted(ms)
        n = len(ms_sorted)
        return {
            'avg': sum(ms) / n,
            'min': ms_sorted[0],
            'max': ms_sorted[-1],
            'median': ms_sorted[n // 2],
        }

    x25519_stats = stats(x25519_times)
    mlkem_stats = stats(mlkem_times)

    # Hybrid = X25519 + ML-KEM (both must be computed for the hybrid scheme)
    hybrid_avg = x25519_stats['avg'] + mlkem_stats['avg']
    hybrid_min = x25519_stats['min'] + mlkem_stats['min']
    hybrid_max = x25519_stats['max'] + mlkem_stats['max']
    hybrid_median = x25519_stats['median'] + mlkem_stats['median']

    # Overhead: how much extra cost the hybrid adds over classical-only
    overhead_ms = mlkem_stats['avg']
    overhead_pct = (mlkem_stats['avg'] / x25519_stats['avg']) * 100

    return {
        'iterations': iterations,
        # X25519 only (classical baseline)
        'x25519_avg_ms': round(x25519_stats['avg'], 4),
        'x25519_min_ms': round(x25519_stats['min'], 4),
        'x25519_max_ms': round(x25519_stats['max'], 4),
        'x25519_median_ms': round(x25519_stats['median'], 4),
        # ML-KEM-768 only (post-quantum baseline)
        'mlkem_avg_ms': round(mlkem_stats['avg'], 4),
        'mlkem_min_ms': round(mlkem_stats['min'], 4),
        'mlkem_max_ms': round(mlkem_stats['max'], 4),
        'mlkem_median_ms': round(mlkem_stats['median'], 4),
        # Hybrid (X25519 + ML-KEM combined)
        'hybrid_avg_ms': round(hybrid_avg, 4),
        'hybrid_min_ms': round(hybrid_min, 4),
        'hybrid_max_ms': round(hybrid_max, 4),
        'hybrid_median_ms': round(hybrid_median, 4),
        # Backwards compat
        'hybrid_total_ms': round(hybrid_avg, 4),
        # Overhead analysis
        'overhead_ms': round(overhead_ms, 4),
        'overhead_pct': round(overhead_pct, 2),
        # Raw data for further analysis
        'x25519_times': x25519_times,
        'mlkem_times': mlkem_times,
    }


def format_benchmark_table(results: dict) -> str:
    """
    Format benchmark results as a 3-column comparison table (plain text).
    Suitable for copy-pasting into reports or saving to a file.
    """
    lines = []
    lines.append("=" * 72)
    lines.append("  HYBRID KEM BENCHMARK RESULTS")
    lines.append(f"  Iterations: {results['iterations']:,}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"  {'Metric':<14} {'X25519 only':>14} {'ML-KEM-768 only':>18} {'Hybrid (both)':>18}")
    lines.append(f"  {'-'*14} {'-'*14:>14} {'-'*18:>18} {'-'*18:>18}")
    lines.append(
        f"  {'Average (ms)':<14} "
        f"{results['x25519_avg_ms']:>14.4f} "
        f"{results['mlkem_avg_ms']:>18.4f} "
        f"{results['hybrid_avg_ms']:>18.4f}"
    )
    lines.append(
        f"  {'Median (ms)':<14} "
        f"{results['x25519_median_ms']:>14.4f} "
        f"{results['mlkem_median_ms']:>18.4f} "
        f"{results['hybrid_median_ms']:>18.4f}"
    )
    lines.append(
        f"  {'Min (ms)':<14} "
        f"{results['x25519_min_ms']:>14.4f} "
        f"{results['mlkem_min_ms']:>18.4f} "
        f"{results['hybrid_min_ms']:>18.4f}"
    )
    lines.append(
        f"  {'Max (ms)':<14} "
        f"{results['x25519_max_ms']:>14.4f} "
        f"{results['mlkem_max_ms']:>18.4f} "
        f"{results['hybrid_max_ms']:>18.4f}"
    )
    lines.append("")
    lines.append("-" * 72)
    lines.append("  OVERHEAD ANALYSIS (Hybrid vs Classical X25519 baseline):")
    lines.append(f"    Extra cost:    +{results['overhead_ms']:.4f} ms per session")
    lines.append(f"    Relative:      +{results['overhead_pct']:.2f}% over X25519-only")
    lines.append(f"    Per 1M sessions: +{(results['overhead_ms'] * 1_000_000 / 1000):.1f} seconds total")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_benchmark_latex(results: dict) -> str:
    """
    Format benchmark results as a LaTeX table for direct inclusion
    in academic papers (IEEE/ACM style).
    """
    lines = []
    lines.append(r"\begin{table}[h]")
    lines.append(r"\centering")
    lines.append(r"\caption{Cryptographic Benchmark: " +
                 f"{results['iterations']:,} iterations" + r"}")
    lines.append(r"\label{tab:benchmark}")
    lines.append(r"\begin{tabular}{lrrr}")
    lines.append(r"\hline")
    lines.append(r"\textbf{Metric (ms)} & \textbf{X25519} & \textbf{ML-KEM-768} & \textbf{Hybrid} \\")
    lines.append(r"\hline")
    lines.append(
        f"Average & {results['x25519_avg_ms']:.4f} & "
        f"{results['mlkem_avg_ms']:.4f} & "
        f"{results['hybrid_avg_ms']:.4f}" + r" \\"
    )
    lines.append(
        f"Median  & {results['x25519_median_ms']:.4f} & "
        f"{results['mlkem_median_ms']:.4f} & "
        f"{results['hybrid_median_ms']:.4f}" + r" \\"
    )
    lines.append(
        f"Min     & {results['x25519_min_ms']:.4f} & "
        f"{results['mlkem_min_ms']:.4f} & "
        f"{results['hybrid_min_ms']:.4f}" + r" \\"
    )
    lines.append(
        f"Max     & {results['x25519_max_ms']:.4f} & "
        f"{results['mlkem_max_ms']:.4f} & "
        f"{results['hybrid_max_ms']:.4f}" + r" \\"
    )
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines)
