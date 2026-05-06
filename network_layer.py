"""
network_layer.py - TCP Network Layer for Hybrid KEM File Transfer
==================================================================
This module handles the TCP client-server communication protocol:
  - Server (Bob): Listens for connections, generates keys, receives encrypted files
  - Client (Alice): Connects, receives public keys, encrypts and sends files

Protocol flow:
  1. Server generates X25519 + ML-KEM keypairs, sends public keys to Client
  2. Client generates its own X25519 keypair, computes shared secrets
  3. Client encapsulates PQ secret, sends ciphertext + encrypted file to Server
  4. Server decapsulates, derives key, decrypts file

Message format:
  Each message is prefixed with a 4-byte big-endian length header.

Attack simulation hooks:
  - Ciphertext tampering (Scenario 3): Handled in crypto_engine during encryption
  - Broken PQ (Scenario 4): Handled during key derivation
  - Replay attack (Scenario 6): Client reuses old ciphertext/nonce from previous session
"""

import os
import socket
import struct
import tempfile
import json
import time
import hashlib
from typing import Optional, Tuple, Callable

try:
    import psutil
    _psutil_available = True
except ImportError:
    _psutil_available = False


def get_process_ram_mb() -> float:
    """
    Return the current process's RSS memory in MB.
    Uses psutil if available, else returns 0 (silent fallback).
    
    RSS (Resident Set Size) = actual physical RAM used by this Python process,
    NOT including OS disk cache. This is the correct metric for Test Scenario 2
    to prove that chunk-based encryption keeps RAM constant regardless of file size.
    """
    if not _psutil_available:
        return 0.0
    try:
        proc = psutil.Process(os.getpid())
        return proc.memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0

from PyQt6.QtCore import QThread, pyqtSignal

import crypto_engine as ce


# ============================================================
# Network Utility Functions
# ============================================================
def send_msg(sock: socket.socket, data: bytes):
    """Send a length-prefixed message over TCP."""
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)


def recv_msg(sock: socket.socket) -> Optional[bytes]:
    """Receive a length-prefixed message from TCP."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    return _recv_exact(sock, msg_len)


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes from the socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), 65536))
        if not chunk:
            return None
        data += chunk
    return data


def send_file_over_socket(sock: socket.socket, filepath: str, progress_callback=None):
    """
    Send a file over TCP in chunks.
    Protocol: [8 bytes: file_size] [file_data_chunks...]
    """
    file_size = os.path.getsize(filepath)
    sock.sendall(struct.pack('>Q', file_size))

    sent = 0
    with open(filepath, 'rb') as f:
        while sent < file_size:
            chunk = f.read(65536)
            if not chunk:
                break
            sock.sendall(chunk)
            sent += len(chunk)
            if progress_callback:
                progress_callback(sent, file_size)


def recv_file_over_socket(sock: socket.socket, output_path: str, progress_callback=None) -> int:
    """
    Receive a file from TCP.
    Returns the file size received.
    """
    size_data = _recv_exact(sock, 8)
    if not size_data:
        return 0
    file_size = struct.unpack('>Q', size_data)[0]

    received = 0
    with open(output_path, 'wb') as f:
        while received < file_size:
            chunk_size = min(65536, file_size - received)
            chunk = sock.recv(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            received += len(chunk)
            if progress_callback:
                progress_callback(received, file_size)

    return received


# ============================================================
# Server Worker Thread (Bob)
# ============================================================
class ServerWorker(QThread):
    """
    QThread worker that runs the server (receiver/Bob) side.
    
    Flow:
      1. Bind and listen on specified port
      2. On connection: generate X25519 + ML-KEM keypairs
      3. Send public keys to client
      4. Receive client's X25519 public key + ML-KEM ciphertext
      5. Compute classical secret + decapsulate PQ secret
      6. Derive hybrid key via HKDF
      7. Receive encrypted file
      8. Decrypt file with AES-256-GCM
    """
    # Signals for UI updates
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)  # current, total
    finished_signal = pyqtSignal(bool, str)  # success, message
    listening_signal = pyqtSignal()

    def __init__(self, host: str, port: int, save_dir: str,
                 save_encrypted: bool = True, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.save_dir = save_dir
        self.save_encrypted = save_encrypted
        self._running = True
        self.server_socket = None

    def stop(self):
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

    def run(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)
            self.log_signal.emit(f"[SERVER] Listening on {self.host}:{self.port}...")
            self.listening_signal.emit()

            conn = None
            while self._running:
                try:
                    conn, addr = self.server_socket.accept()
                    break
                except socket.timeout:
                    continue

            if not self._running or conn is None:
                self.finished_signal.emit(False, "Server stopped.")
                return

            self.log_signal.emit(f"[SERVER] Connection from {addr}")
            conn.settimeout(30.0)

            # ════════════════════════════════════════════════════════════
            # METRICS COLLECTION (for Test & Discussion section)
            # ════════════════════════════════════════════════════════════
            metrics = {}
            t_session_start = time.perf_counter()
            
            # Baseline RAM (before any work)
            ram_baseline = get_process_ram_mb()
            if ram_baseline > 0:
                self.log_signal.emit(
                    f"[SERVER] [METRIC] RAM baseline (before session): {ram_baseline:.1f} MB"
                )

            # ── Step 1: Generate Keypairs ──
            self.log_signal.emit("[SERVER] Generating X25519 keypair...")
            t0 = time.perf_counter()
            x25519_priv, x25519_pub = ce.generate_x25519_keypair()
            metrics['x25519_keygen_ms'] = (time.perf_counter() - t0) * 1000

            self.log_signal.emit("[SERVER] Generating ML-KEM-768 keypair...")
            t0 = time.perf_counter()
            kem, mlkem_pub, mlkem_sk = ce.generate_mlkem_keypair()
            metrics['mlkem_keygen_ms'] = (time.perf_counter() - t0) * 1000

            self.log_signal.emit(
                f"[SERVER] [METRIC] KeyGen: X25519={metrics['x25519_keygen_ms']:.3f}ms, "
                f"ML-KEM={metrics['mlkem_keygen_ms']:.3f}ms"
            )

            # ── Step 2: Send public keys to Client ──
            # Format: JSON header with key lengths, then raw key bytes
            header = json.dumps({
                'x25519_pub_len': len(x25519_pub),
                'mlkem_pub_len': len(mlkem_pub),
            }).encode()
            send_msg(conn, header)
            send_msg(conn, x25519_pub)
            send_msg(conn, mlkem_pub)
            self.log_signal.emit(f"[SERVER] Sent public keys (X25519: {len(x25519_pub)}B, ML-KEM: {len(mlkem_pub)}B)")

            # Log SERVER X25519 public key (first 16 hex chars) — for replay attack table
            self.log_signal.emit(
                f"[SERVER] [METRIC] Server X25519 pub (first 16B hex): {x25519_pub[:16].hex()}"
            )

            # ── Step 3: Receive Client's X25519 public key + ML-KEM ciphertext ──
            client_header = json.loads(recv_msg(conn).decode())
            client_x25519_pub = recv_msg(conn)
            mlkem_ciphertext = recv_msg(conn)
            filename = client_header.get('filename', 'received_file')
            self.log_signal.emit(f"[SERVER] Received client keys + ciphertext (file: {filename})")

            # ── Step 4: Compute secrets ──
            self.log_signal.emit("[SERVER] Computing X25519 shared secret...")
            t0 = time.perf_counter()
            classical_secret = ce.compute_classical_secret(x25519_priv, client_x25519_pub)
            metrics['x25519_shared_ms'] = (time.perf_counter() - t0) * 1000

            self.log_signal.emit("[SERVER] Decapsulating ML-KEM ciphertext...")
            t0 = time.perf_counter()
            pq_secret = ce.decapsulate_pq(kem, mlkem_ciphertext)
            metrics['mlkem_decap_ms'] = (time.perf_counter() - t0) * 1000

            # ── Step 5: Derive hybrid key ──
            # Server ALWAYS uses both secrets (normal behavior)
            self.log_signal.emit("[SERVER] Deriving hybrid key via HKDF(classical || PQ)...")
            t0 = time.perf_counter()
            final_key = ce.derive_hybrid_key(classical_secret, pq_secret, simulate_broken_pq=False)
            metrics['hkdf_ms'] = (time.perf_counter() - t0) * 1000
            self.log_signal.emit("[SERVER] Hybrid key derived successfully.")

            # Log derived AES key fingerprint (first 8B hex) — for Scenarios 4 & 6 tables
            self.log_signal.emit(
                f"[SERVER] [METRIC] Derived AES key (first 8B hex): {final_key[:8].hex()}"
            )
            self.log_signal.emit(
                f"[SERVER] [METRIC] Asymmetric phase total: "
                f"{metrics['x25519_shared_ms'] + metrics['mlkem_decap_ms'] + metrics['hkdf_ms']:.3f}ms"
            )

            # ── Step 6: Receive encrypted file ──
            self.log_signal.emit("[SERVER] Receiving encrypted file...")
            
            # Determine where to save the encrypted file
            if self.save_encrypted:
                # Save permanently in a subfolder for proof
                enc_dir = os.path.join(self.save_dir, "received_encrypted")
                os.makedirs(enc_dir, exist_ok=True)
                enc_path = os.path.join(enc_dir, filename + ".enc")
            else:
                enc_path = os.path.join(tempfile.gettempdir(), "hybrid_kem_received.enc")
            
            t0 = time.perf_counter()
            recv_file_over_socket(
                conn, enc_path,
                progress_callback=lambda cur, tot: self.progress_signal.emit(cur, tot)
            )
            metrics['network_recv_ms'] = (time.perf_counter() - t0) * 1000
            enc_size = os.path.getsize(enc_path)
            self.log_signal.emit(f"[SERVER] Encrypted file received ({enc_size} bytes)")
            self.log_signal.emit(
                f"[SERVER] [METRIC] Network receive time: {metrics['network_recv_ms']:.2f}ms"
            )
            if self.save_encrypted:
                self.log_signal.emit(f"[SERVER] 🔒 Encrypted file saved at: {enc_path}")

            # ── Step 7: Decrypt file ──
            self.log_signal.emit("[SERVER] Decrypting with AES-256-GCM...")
            output_path = os.path.join(self.save_dir, filename)
            
            try:
                # Start a background thread to sample RAM during decryption (peak tracking)
                import threading
                ram_samples = [get_process_ram_mb()]
                stop_sampling = threading.Event()

                def sample_ram():
                    while not stop_sampling.is_set():
                        ram_samples.append(get_process_ram_mb())
                        time.sleep(0.05)  # sample every 50ms

                sampler_thread = None
                if _psutil_available:
                    sampler_thread = threading.Thread(target=sample_ram, daemon=True)
                    sampler_thread.start()

                t0 = time.perf_counter()
                ce.decrypt_file_chunked(
                    enc_path, output_path, final_key,
                    progress_callback=lambda cur, tot: self.progress_signal.emit(cur, tot)
                )
                metrics['aes_decrypt_ms'] = (time.perf_counter() - t0) * 1000

                # Stop sampling and compute peak
                if sampler_thread:
                    stop_sampling.set()
                    sampler_thread.join(timeout=1.0)
                    ram_samples.append(get_process_ram_mb())

                peak_ram = max(ram_samples) if ram_samples else 0.0
                ram_delta = peak_ram - ram_baseline
                self.log_signal.emit("[SERVER] ✓ AES-256-GCM Tag Verified! File decrypted successfully.")

                # Compute SHA-256 hash of recovered file (for Test 1 integrity proof)
                sha256 = hashlib.sha256()
                with open(output_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)
                file_hash = sha256.hexdigest()
                output_size = os.path.getsize(output_path)
                
                metrics['total_session_ms'] = (time.perf_counter() - t_session_start) * 1000
                throughput_mbps = (output_size / (1024 * 1024)) / (metrics['aes_decrypt_ms'] / 1000) \
                    if metrics['aes_decrypt_ms'] > 0 else 0

                self.log_signal.emit(f"[SERVER] [METRIC] AES-GCM decrypt: {metrics['aes_decrypt_ms']:.2f}ms")
                self.log_signal.emit(
                    f"[SERVER] [METRIC] Decrypt throughput: {throughput_mbps:.1f} MB/s"
                )
                if _psutil_available:
                    self.log_signal.emit(
                        f"[SERVER] [METRIC] Peak process RAM during decrypt: {peak_ram:.1f} MB "
                        f"(Δ from baseline: +{ram_delta:.1f} MB)"
                    )
                else:
                    self.log_signal.emit(
                        "[SERVER] [METRIC] (Install psutil for RAM measurements: pip install psutil)"
                    )
                self.log_signal.emit(
                    f"[SERVER] [METRIC] Recovered file size: {output_size} bytes"
                )
                self.log_signal.emit(
                    f"[SERVER] [METRIC] Recovered file SHA-256: {file_hash}"
                )
                self.log_signal.emit(
                    f"[SERVER] [METRIC] TOTAL session time: {metrics['total_session_ms']:.2f}ms"
                )

                self.log_signal.emit(f"[SERVER] File saved to: {output_path}")
                self.finished_signal.emit(True, f"File received and decrypted: {output_path}")
            except Exception as e:
                error_msg = str(e)
                if "InvalidTag" in type(e).__name__ or "tag" in error_msg.lower():
                    self.log_signal.emit("[SERVER] ✗ INTEGRITY CHECK FAILED (Authentication Tag Mismatch)!")
                    self.log_signal.emit("[SERVER] The ciphertext has been tampered with. File rejected.")
                    # Remove partial file
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    self.finished_signal.emit(False, "Integrity Check Failed: Authentication Tag Mismatch")
                else:
                    self.log_signal.emit(f"[SERVER] ✗ Decryption FAILED: {error_msg}")
                    self.log_signal.emit("[SERVER] Possible key mismatch (hybrid mechanism protection active).")
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    self.finished_signal.emit(False, f"Decryption failed: {error_msg}")

            # Cleanup temp file (only if not saved as proof)
            if not self.save_encrypted and os.path.exists(enc_path):
                os.remove(enc_path)

            conn.close()

        except Exception as e:
            self.log_signal.emit(f"[SERVER] Error: {str(e)}")
            self.finished_signal.emit(False, str(e))
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass


# ============================================================
# Client Worker Thread (Alice)
# ============================================================
class ClientWorker(QThread):
    """
    QThread worker that runs the client (sender/Alice) side.
    
    Flow:
      1. Connect to server
      2. Receive server's public keys
      3. Generate own X25519 keypair, compute classical secret
      4. Encapsulate PQ secret with server's ML-KEM public key
      5. Derive hybrid key via HKDF
      6. Encrypt file with AES-256-GCM
      7. Send X25519 public key + ML-KEM ciphertext + encrypted file
    
    Attack hooks:
      - simulate_tampering: Flip byte in ciphertext (Scenario 3)
      - simulate_broken_pq: Omit PQ secret from HKDF (Scenario 4)
      - simulate_replay: Reuse old ciphertext/nonce (Scenario 6)
    """
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal(bool, str)

    # ════════════════════════════════════════════════════════════════
    # REPLAY ATTACK STORAGE (Scenario 6)
    # ════════════════════════════════════════════════════════════════
    # This class-level dict captures the RAW BYTES that an attacker
    # could observe on the wire during a real session (Wireshark-style).
    # It contains ONLY data an attacker would have access to:
    #   - client_x25519_pub_bytes: Alice's public key (sent in clear)
    #   - mlkem_ciphertext_bytes: PQ ciphertext (sent in clear)
    #   - encrypted_file_bytes: the AES-GCM encrypted payload
    #
    # CRUCIALLY, it does NOT contain:
    #   - Alice's X25519 PRIVATE key (never on the wire)
    #   - The final hybrid AES key (never on the wire)
    #   - The plaintext file
    #
    # When replay is triggered, the client acts as an attacker:
    # it ignores the server's NEW public keys and replays the OLD bytes
    # verbatim, simulating an MITM/Wireshark replay.
    # ════════════════════════════════════════════════════════════════
    _captured_session = None

    def __init__(
        self, host: str, port: int, file_path: str,
        simulate_tampering: bool = False,
        simulate_broken_pq: bool = False,
        simulate_replay: bool = False,
        save_encrypted: bool = True,
        parent=None
    ):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.file_path = file_path
        self.simulate_tampering = simulate_tampering
        self.simulate_broken_pq = simulate_broken_pq
        self.simulate_replay = simulate_replay
        self.save_encrypted = save_encrypted

    def run(self):
        sock = None
        try:
            # ── Connect to Server ──
            self.log_signal.emit(f"[CLIENT] Connecting to {self.host}:{self.port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            sock.connect((self.host, self.port))
            self.log_signal.emit("[CLIENT] Connected to server.")

            # ── Receive Server's Public Keys ──
            header = json.loads(recv_msg(sock).decode())
            server_x25519_pub = recv_msg(sock)
            server_mlkem_pub = recv_msg(sock)
            self.log_signal.emit(
                f"[CLIENT] Received server public keys "
                f"(X25519: {len(server_x25519_pub)}B, ML-KEM: {len(server_mlkem_pub)}B)"
            )

            # ════════════════════════════════════════════════════════════
            # REPLAY ATTACK BRANCH (Scenario 6 - REAL replay)
            # ════════════════════════════════════════════════════════════
            if self.simulate_replay:
                if ClientWorker._captured_session is None:
                    self.log_signal.emit(
                        "[CLIENT] ⚠ REPLAY ATTACK requested but no captured session exists."
                    )
                    self.log_signal.emit(
                        "[CLIENT] → Run a NORMAL transfer first (replay OFF) to capture session bytes,"
                    )
                    self.log_signal.emit(
                        "[CLIENT]   then enable replay and try again."
                    )
                    self.finished_signal.emit(False, "No captured session for replay.")
                    return

                cap = ClientWorker._captured_session
                self.log_signal.emit("[CLIENT] ⚠ REPLAYING captured session bytes (Wireshark-style)")
                self.log_signal.emit(
                    f"[CLIENT] → Server sent NEW ephemeral keys (ignored): "
                    f"X25519 pub starts with {server_x25519_pub[:4].hex()}..."
                )
                self.log_signal.emit(
                    f"[CLIENT] → Replaying OLD client pub: starts with {cap['client_x25519_pub'][:4].hex()}..."
                )
                self.log_signal.emit(
                    f"[CLIENT] → Replaying OLD ML-KEM ciphertext ({len(cap['mlkem_ciphertext'])} bytes)"
                )

                # Check that the captured encrypted file still exists on disk
                captured_enc_path = cap.get('encrypted_file_path')
                if not captured_enc_path or not os.path.exists(captured_enc_path):
                    self.log_signal.emit(
                        "[CLIENT] ✗ Captured encrypted file no longer exists on disk."
                    )
                    self.log_signal.emit(
                        "[CLIENT] → Run a fresh normal transfer (with 'Save encrypted file' ON)."
                    )
                    self.finished_signal.emit(False, "Captured file missing.")
                    return

                # Send the OLD bytes verbatim (no key derivation, no encryption — pure replay)
                client_header = json.dumps({
                    'x25519_pub_len': len(cap['client_x25519_pub']),
                    'mlkem_ct_len': len(cap['mlkem_ciphertext']),
                    'filename': cap['filename'],
                }).encode()
                send_msg(sock, client_header)
                send_msg(sock, cap['client_x25519_pub'])
                send_msg(sock, cap['mlkem_ciphertext'])

                # Replay the encrypted file STREAMING from disk (chunk-based, no full-memory load)
                replay_size = os.path.getsize(captured_enc_path)
                self.log_signal.emit(
                    f"[CLIENT] → Replaying OLD encrypted file ({replay_size} bytes) "
                    "streamed from disk"
                )
                send_file_over_socket(
                    sock, captured_enc_path,
                    progress_callback=lambda cur, tot: self.progress_signal.emit(cur, tot)
                )

                self.log_signal.emit("[CLIENT] Replay payload sent. Server should REJECT it.")
                self.log_signal.emit(
                    "[CLIENT] (Reason: server's NEW ephemeral keys → different shared secrets → "
                    "different AES key → GCM tag mismatch on decryption)"
                )
                self.finished_signal.emit(True, "Replay attack payload sent (expecting server rejection).")
                return
            # ════════════════════════════════════════════════════════════

            # ── Normal Operation: Generate Fresh Keys ──

            # ════════════════════════════════════════════════════════════
            # METRICS COLLECTION (Client side)
            # ════════════════════════════════════════════════════════════
            metrics = {}
            t_session_start = time.perf_counter()
            
            # Baseline RAM (before any work)
            ram_baseline = get_process_ram_mb()
            if ram_baseline > 0:
                self.log_signal.emit(
                    f"[CLIENT] [METRIC] RAM baseline (before session): {ram_baseline:.1f} MB"
                )

            # Compute SHA-256 of original file (for Test 1 integrity proof)
            sha256 = hashlib.sha256()
            with open(self.file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            original_hash = sha256.hexdigest()
            self.log_signal.emit(
                f"[CLIENT] [METRIC] Original file SHA-256: {original_hash}"
            )

            # Generate Alice's X25519 keypair
            self.log_signal.emit("[CLIENT] Generating ephemeral X25519 keypair...")
            t0 = time.perf_counter()
            alice_x25519_priv, alice_x25519_pub = ce.generate_x25519_keypair()
            metrics['x25519_keygen_ms'] = (time.perf_counter() - t0) * 1000
            client_x25519_pub = alice_x25519_pub

            # Log CLIENT X25519 public key (first 16 hex chars) — for replay attack table
            self.log_signal.emit(
                f"[CLIENT] [METRIC] Client X25519 pub (first 16B hex): {client_x25519_pub[:16].hex()}"
            )

            # Compute classical shared secret
            self.log_signal.emit("[CLIENT] Computing X25519 shared secret...")
            t0 = time.perf_counter()
            classical_secret = ce.compute_classical_secret(
                alice_x25519_priv, server_x25519_pub
            )
            metrics['x25519_shared_ms'] = (time.perf_counter() - t0) * 1000

            # Encapsulate PQ secret
            self.log_signal.emit("[CLIENT] Encapsulating ML-KEM-768 secret...")
            t0 = time.perf_counter()
            mlkem_ciphertext, pq_secret = ce.encapsulate_pq(server_mlkem_pub)
            metrics['mlkem_encap_ms'] = (time.perf_counter() - t0) * 1000
            self.log_signal.emit(f"[CLIENT] ML-KEM ciphertext size: {len(mlkem_ciphertext)} bytes")

            # ── Derive Hybrid Key ──
            if self.simulate_broken_pq:
                self.log_signal.emit("[CLIENT] ⚠ SIMULATING BROKEN PQ: Omitting PQ secret from HKDF!")

            self.log_signal.emit("[CLIENT] Deriving hybrid key via HKDF...")
            t0 = time.perf_counter()
            final_key = ce.derive_hybrid_key(
                classical_secret, pq_secret,
                simulate_broken_pq=self.simulate_broken_pq
            )
            metrics['hkdf_ms'] = (time.perf_counter() - t0) * 1000
            self.log_signal.emit("[CLIENT] Hybrid key derived.")

            # Log derived AES key fingerprint (first 8B hex) — for Scenarios 4 & 6 tables
            self.log_signal.emit(
                f"[CLIENT] [METRIC] Derived AES key (first 8B hex): {final_key[:8].hex()}"
            )

            # ── Send Client's Keys + Ciphertext ──
            filename = os.path.basename(self.file_path)
            client_header = json.dumps({
                'x25519_pub_len': len(client_x25519_pub),
                'mlkem_ct_len': len(mlkem_ciphertext),
                'filename': filename,
            }).encode()
            send_msg(sock, client_header)
            send_msg(sock, client_x25519_pub)
            send_msg(sock, mlkem_ciphertext)
            self.log_signal.emit("[CLIENT] Sent client keys and ML-KEM ciphertext.")

            # ── Encrypt File ──
            if self.simulate_tampering:
                self.log_signal.emit("[CLIENT] ⚠ CIPHERTEXT TAMPERING ENABLED: Will flip 1 byte!")
            
            self.log_signal.emit(f"[CLIENT] Encrypting file: {filename}")
            
            # Determine where to save the encrypted file
            if self.save_encrypted:
                # Save permanently next to the source file for proof
                src_dir = os.path.dirname(os.path.abspath(self.file_path))
                enc_dir = os.path.join(src_dir, "sent_encrypted")
                os.makedirs(enc_dir, exist_ok=True)
                enc_path = os.path.join(enc_dir, filename + ".enc")
            else:
                enc_path = os.path.join(tempfile.gettempdir(), "hybrid_kem_send.enc")
            
            # Background RAM sampler during encryption (peak tracking)
            import threading
            ram_samples = [get_process_ram_mb()]
            stop_sampling = threading.Event()

            def sample_ram_client():
                while not stop_sampling.is_set():
                    ram_samples.append(get_process_ram_mb())
                    time.sleep(0.05)

            sampler_thread = None
            if _psutil_available:
                sampler_thread = threading.Thread(target=sample_ram_client, daemon=True)
                sampler_thread.start()

            t0 = time.perf_counter()
            ce.encrypt_file_chunked(
                self.file_path, enc_path, final_key,
                simulate_tampering=self.simulate_tampering,
                progress_callback=lambda cur, tot: self.progress_signal.emit(cur, tot)
            )
            metrics['aes_encrypt_ms'] = (time.perf_counter() - t0) * 1000
            
            # Stop sampling
            if sampler_thread:
                stop_sampling.set()
                sampler_thread.join(timeout=1.0)
                ram_samples.append(get_process_ram_mb())
            peak_ram_encrypt = max(ram_samples) if ram_samples else 0.0
            ram_delta_encrypt = peak_ram_encrypt - ram_baseline
            
            enc_size = os.path.getsize(enc_path)
            orig_size = os.path.getsize(self.file_path)
            throughput_mbps = (orig_size / (1024 * 1024)) / (metrics['aes_encrypt_ms'] / 1000) \
                if metrics['aes_encrypt_ms'] > 0 else 0
            
            self.log_signal.emit(
                f"[CLIENT] File encrypted. Original: {orig_size} bytes → "
                f"Encrypted: {enc_size} bytes (overhead: {enc_size - orig_size} bytes)"
            )
            self.log_signal.emit(
                f"[CLIENT] [METRIC] AES-GCM encrypt: {metrics['aes_encrypt_ms']:.2f}ms "
                f"(throughput: {throughput_mbps:.1f} MB/s)"
            )
            if _psutil_available:
                self.log_signal.emit(
                    f"[CLIENT] [METRIC] Peak process RAM during encrypt: {peak_ram_encrypt:.1f} MB "
                    f"(Δ from baseline: +{ram_delta_encrypt:.1f} MB)"
                )
            if self.save_encrypted:
                self.log_signal.emit(f"[CLIENT] 🔒 Encrypted file saved at: {enc_path}")
            self.log_signal.emit("[CLIENT] Sending over network...")

            # ── Send Encrypted File ──
            t0 = time.perf_counter()
            send_file_over_socket(
                sock, enc_path,
                progress_callback=lambda cur, tot: self.progress_signal.emit(cur, tot)
            )
            metrics['network_send_ms'] = (time.perf_counter() - t0) * 1000
            metrics['total_session_ms'] = (time.perf_counter() - t_session_start) * 1000
            
            self.log_signal.emit("[CLIENT] ✓ Encrypted file sent successfully.")
            self.log_signal.emit(
                f"[CLIENT] [METRIC] Network send: {metrics['network_send_ms']:.2f}ms"
            )
            self.log_signal.emit(
                f"[CLIENT] [METRIC] TOTAL session time: {metrics['total_session_ms']:.2f}ms"
            )

            # ════════════════════════════════════════════════════════════
            # CAPTURE SESSION FOR REPLAY ATTACK TESTING (Scenario 6)
            # ════════════════════════════════════════════════════════════
            # Save the path to the encrypted file (not the bytes!) so
            # that replay can stream it back without loading it to RAM.
            # This preserves the chunk-based memory guarantee for large files.
            # NO private keys, NO derived AES key are captured — only
            # what an eavesdropper would observe on the wire.
            # ════════════════════════════════════════════════════════════
            if (not self.simulate_tampering and not self.simulate_broken_pq
                    and self.save_encrypted):
                # Only capture when the encrypted file is persisted on disk
                # (otherwise we'd need to copy the temp file, defeating the point)
                ClientWorker._captured_session = {
                    'client_x25519_pub': client_x25519_pub,
                    'mlkem_ciphertext': mlkem_ciphertext,
                    'encrypted_file_path': enc_path,  # path, not bytes
                    'filename': filename,
                }
                self.log_signal.emit(
                    "[CLIENT] 📼 Session captured for replay testing "
                    f"(ref to {os.path.basename(enc_path)})"
                )

            self.finished_signal.emit(True, "File encrypted and sent.")

            # Cleanup (only if not saved as proof)
            if not self.save_encrypted and os.path.exists(enc_path):
                os.remove(enc_path)

        except ConnectionRefusedError:
            self.log_signal.emit("[CLIENT] ✗ Connection refused. Is the server running?")
            self.finished_signal.emit(False, "Connection refused.")
        except Exception as e:
            self.log_signal.emit(f"[CLIENT] ✗ Error: {str(e)}")
            self.finished_signal.emit(False, str(e))
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass


# ============================================================
# Benchmark Worker Thread (Test Scenario 5)
# ============================================================
class BenchmarkWorker(QThread):
    """
    QThread worker that runs the cryptographic benchmark
    (Test Scenario 5) without blocking the UI.
    """
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal(dict)

    def __init__(self, iterations: int = 10000, parent=None):
        super().__init__(parent)
        self.iterations = iterations

    def run(self):
        self.log_signal.emit(f"[BENCHMARK] Starting {self.iterations}-iteration benchmark...")
        self.log_signal.emit("[BENCHMARK] Phase A: X25519 KeyGen + SharedSecret...")

        def progress_cb(current, total, phase):
            self.progress_signal.emit(current, total)
            if current % 2000 == 0:
                self.log_signal.emit(f"[BENCHMARK] {phase}: {current}/{total // 2} iterations...")

        results = ce.run_benchmark(
            iterations=self.iterations,
            progress_callback=progress_cb
        )

        self.log_signal.emit("[BENCHMARK] ─── Results ───")
        # Print the comparison table
        table = ce.format_benchmark_table(results)
        for line in table.split("\n"):
            self.log_signal.emit(f"[BENCHMARK] {line}")
        self.log_signal.emit("[BENCHMARK] ─── Complete ───")

        # Save results to file for reporting
        try:
            import os
            out_path = os.path.join(os.getcwd(), "benchmark_results.txt")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ce.format_benchmark_table(results))
                f.write("\n\n")
                f.write("LaTeX table (paste into your paper):\n")
                f.write("-" * 72 + "\n")
                f.write(ce.format_benchmark_latex(results))
                f.write("\n")
            self.log_signal.emit(f"[BENCHMARK] Results saved to: {out_path}")
        except Exception as e:
            self.log_signal.emit(f"[BENCHMARK] Could not save file: {e}")

        self.finished_signal.emit(results)
