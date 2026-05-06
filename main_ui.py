"""
main_ui.py - PyQt6 User Interface for Hybrid KEM Secure File Transfer
======================================================================
This is the main entry point for the application. It provides:

  - Main Tab: Server/Client controls, IP/Port, file picker, send button
  - Test Scenarios Tab: Attack simulation toggles + benchmark button
  - Real-time log viewer and progress bar

Run with: python main_ui.py

Requirements:
  pip install PyQt6 cryptography liboqs-python
"""

import sys
import os
import tempfile

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QGroupBox, QLabel, QLineEdit, QPushButton,
    QTextEdit, QProgressBar, QFileDialog, QCheckBox, QSpinBox,
    QGridLayout, QFrame, QSplitter, QMessageBox, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QIcon

from network_layer import ServerWorker, ClientWorker, BenchmarkWorker


class HybridKEMApp(QMainWindow):
    """Main application window for Hybrid KEM File Transfer."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hybrid KEM Secure File Transfer — ML-KEM-768 + X25519")
        self.setMinimumSize(900, 700)
        self.resize(1000, 750)

        # State
        self.server_worker = None
        self.client_worker = None
        self.benchmark_worker = None
        self.selected_file = None
        self.save_dir = tempfile.gettempdir()

        self._build_ui()
        self._connect_signals()

    # ================================================================
    # UI Construction
    # ================================================================
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # ── Title Bar ──
        title_label = QLabel("🔐 Hybrid KEM Secure File Transfer")
        title_font = QFont("Segoe UI", 16, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        subtitle = QLabel("X25519 (Classical ECDH) + ML-KEM-768 (Post-Quantum Kyber) + AES-256-GCM")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666; font-size: 11px; margin-bottom: 8px;")
        main_layout.addWidget(subtitle)

        # ── Tab Widget ──
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: Main Transfer
        self.tabs.addTab(self._build_main_tab(), "📡 File Transfer")

        # Tab 2: Test Scenarios
        self.tabs.addTab(self._build_test_tab(), "🧪 Test Scenarios & Attacks")

        # ── Progress Bar ──
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(22)
        main_layout.addWidget(self.progress_bar)

        # ── Log Viewer ──
        log_label = QLabel("📋 Real-Time Cryptographic Log:")
        log_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        main_layout.addWidget(log_label)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        self.log_view.setStyleSheet(
            "background-color: #1e1e2e; color: #cdd6f4; "
            "border: 1px solid #45475a; border-radius: 4px; padding: 4px;"
        )
        self.log_view.setMinimumHeight(200)
        main_layout.addWidget(self.log_view)

        # ── Status Bar ──
        self.statusBar().showMessage("Ready. Configure server or client to begin.")

    def _build_main_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # ── Network Settings ──
        net_group = QGroupBox("Network Settings")
        net_layout = QGridLayout()

        net_layout.addWidget(QLabel("IP Address:"), 0, 0)
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setPlaceholderText("e.g. 127.0.0.1")
        net_layout.addWidget(self.ip_input, 0, 1)

        net_layout.addWidget(QLabel("Port:"), 0, 2)
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(9876)
        net_layout.addWidget(self.port_input, 0, 3)

        net_group.setLayout(net_layout)
        layout.addWidget(net_group)

        # ── Server Controls ──
        server_group = QGroupBox("Server (Receiver / Bob)")
        server_layout = QHBoxLayout()

        self.btn_start_server = QPushButton("▶ Start Server")
        self.btn_start_server.setStyleSheet(
            "QPushButton { background-color: #40a02b; color: white; "
            "font-weight: bold; padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #37892a; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        server_layout.addWidget(self.btn_start_server)

        self.btn_stop_server = QPushButton("⏹ Stop Server")
        self.btn_stop_server.setEnabled(False)
        self.btn_stop_server.setStyleSheet(
            "QPushButton { background-color: #e64553; color: white; "
            "font-weight: bold; padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #c43a47; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        server_layout.addWidget(self.btn_stop_server)

        server_layout.addWidget(QLabel("Save Dir:"))
        self.save_dir_input = QLineEdit(self.save_dir)
        self.save_dir_input.setReadOnly(True)
        server_layout.addWidget(self.save_dir_input)

        self.btn_browse_save = QPushButton("📁 Browse")
        server_layout.addWidget(self.btn_browse_save)

        server_group.setLayout(server_layout)
        layout.addWidget(server_group)

        # ── Client Controls ──
        client_group = QGroupBox("Client (Sender / Alice)")
        client_layout = QVBoxLayout()

        # File selection row
        file_row = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #888; font-style: italic;")
        file_row.addWidget(self.file_label)

        self.btn_browse_file = QPushButton("📂 Browse File")
        file_row.addWidget(self.btn_browse_file)
        client_layout.addLayout(file_row)

        # Send button
        self.btn_send = QPushButton("🚀 Encrypt & Send File")
        self.btn_send.setEnabled(False)
        self.btn_send.setStyleSheet(
            "QPushButton { background-color: #1e66f5; color: white; "
            "font-weight: bold; padding: 10px 24px; border-radius: 4px; font-size: 13px; }"
            "QPushButton:hover { background-color: #1856d1; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        client_layout.addWidget(self.btn_send)

        # Save encrypted file checkbox (proof of encryption)
        self.chk_save_encrypted = QCheckBox(
            "💾 Save encrypted file as proof (creates 'sent_encrypted/' and 'received_encrypted/' folders)"
        )
        self.chk_save_encrypted.setChecked(True)
        self.chk_save_encrypted.setToolTip(
            "When enabled, the encrypted .enc file is preserved on both sender and receiver sides.\n"
            "You can open it in a hex editor to verify the file is unreadable binary data."
        )
        self.chk_save_encrypted.setStyleSheet("color: #555; font-size: 11px;")
        client_layout.addWidget(self.chk_save_encrypted)

        client_group.setLayout(client_layout)
        layout.addWidget(client_group)

        layout.addStretch()
        return tab

    def _build_test_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info_label = QLabel(
            "These toggles enable attack simulation hooks in the cryptographic pipeline.\n"
            "Enable a toggle BEFORE sending a file to observe the corresponding failure mode."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #555; font-size: 11px; margin-bottom: 10px;")
        layout.addWidget(info_label)

        # ── Scenario 3: Ciphertext Tampering ──
        s3_group = QGroupBox("Scenario 3: AES-GCM Integrity Violation")
        s3_layout = QVBoxLayout()
        self.chk_tampering = QCheckBox("Simulate Ciphertext Tampering")
        self.chk_tampering.setToolTip(
            "Flips 1 random byte in the AES ciphertext before sending.\n"
            "The server should detect this via GCM authentication tag mismatch."
        )
        s3_desc = QLabel(
            "Flips 1 random byte in AES ciphertext → Server detects via GCM tag mismatch → File rejected."
        )
        s3_desc.setWordWrap(True)
        s3_desc.setStyleSheet("color: #666; font-size: 10px;")
        s3_layout.addWidget(self.chk_tampering)
        s3_layout.addWidget(s3_desc)
        s3_group.setLayout(s3_layout)
        layout.addWidget(s3_group)

        # ── Scenario 4: Broken PQ Algorithm ──
        s4_group = QGroupBox("Scenario 4: Cracking a Single Algorithm")
        s4_layout = QVBoxLayout()
        self.chk_broken_pq = QCheckBox("Simulate Broken PQ Algorithm")
        self.chk_broken_pq.setToolTip(
            "Client omits PQ secret from HKDF → derives different key than server.\n"
            "Proves: even if PQ is broken, classical secret still protects the system."
        )
        s4_desc = QLabel(
            "Client derives key using ONLY X25519 secret (omits PQ) → Key mismatch → Decryption fails."
        )
        s4_desc.setWordWrap(True)
        s4_desc.setStyleSheet("color: #666; font-size: 10px;")
        s4_layout.addWidget(self.chk_broken_pq)
        s4_layout.addWidget(s4_desc)
        s4_group.setLayout(s4_layout)
        layout.addWidget(s4_group)

        # ── Scenario 6: Replay Attack ──
        s6_group = QGroupBox("Scenario 6: Replay Attack")
        s6_layout = QVBoxLayout()
        self.chk_replay = QCheckBox("Simulate Replay Attack")
        self.chk_replay.setToolTip(
            "Reuses ML-KEM ciphertext and X25519 public key from the previous session.\n"
            "New server generates fresh ephemeral keys → old data produces wrong shared secret."
        )
        s6_desc = QLabel(
            "Reuses previous session's ciphertext + public key → Server's new ephemeral keys → Rejection."
        )
        s6_desc.setWordWrap(True)
        s6_desc.setStyleSheet("color: #666; font-size: 10px;")
        s6_layout.addWidget(self.chk_replay)
        s6_layout.addWidget(s6_desc)
        s6_group.setLayout(s6_layout)
        layout.addWidget(s6_group)

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("color: #ddd;")
        layout.addWidget(separator)

        # ── Scenario 5: Benchmark ──
        s5_group = QGroupBox("Scenario 5: Cryptographic Transaction Delay (Benchmark)")
        s5_layout = QVBoxLayout()

        bench_row = QHBoxLayout()
        bench_row.addWidget(QLabel("Iterations:"))
        self.bench_iterations = QSpinBox()
        self.bench_iterations.setRange(100, 50000)
        self.bench_iterations.setValue(10000)
        self.bench_iterations.setSingleStep(1000)
        bench_row.addWidget(self.bench_iterations)

        self.btn_benchmark = QPushButton("⏱ Run Benchmark")
        self.btn_benchmark.setStyleSheet(
            "QPushButton { background-color: #df8e1d; color: white; "
            "font-weight: bold; padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #c47f1a; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        bench_row.addWidget(self.btn_benchmark)
        s5_layout.addLayout(bench_row)

        s5_desc = QLabel(
            "Runs X25519 and ML-KEM-768 operations N times, measures average latency in ms."
        )
        s5_desc.setWordWrap(True)
        s5_desc.setStyleSheet("color: #666; font-size: 10px;")
        s5_layout.addWidget(s5_desc)
        s5_group.setLayout(s5_layout)
        layout.addWidget(s5_group)

        layout.addStretch()
        return tab

    # ================================================================
    # Signal Connections
    # ================================================================
    def _connect_signals(self):
        self.btn_start_server.clicked.connect(self._start_server)
        self.btn_stop_server.clicked.connect(self._stop_server)
        self.btn_browse_save.clicked.connect(self._browse_save_dir)
        self.btn_browse_file.clicked.connect(self._browse_file)
        self.btn_send.clicked.connect(self._send_file)
        self.btn_benchmark.clicked.connect(self._run_benchmark)

    # ================================================================
    # Server Actions
    # ================================================================
    def _start_server(self):
        host = self.ip_input.text().strip()
        port = self.port_input.value()
        self.save_dir = self.save_dir_input.text().strip()

        self.server_worker = ServerWorker(
            host, port, self.save_dir,
            save_encrypted=self.chk_save_encrypted.isChecked()
        )
        self.server_worker.log_signal.connect(self._append_log)
        self.server_worker.progress_signal.connect(self._update_progress)
        self.server_worker.finished_signal.connect(self._on_server_finished)
        self.server_worker.listening_signal.connect(self._on_server_listening)
        self.server_worker.start()

        self.btn_start_server.setEnabled(False)
        self.btn_stop_server.setEnabled(True)
        self.statusBar().showMessage("Starting server...")

    def _stop_server(self):
        if self.server_worker:
            self.server_worker.stop()
            self.server_worker.wait(3000)
            self.server_worker = None
        self.btn_start_server.setEnabled(True)
        self.btn_stop_server.setEnabled(False)
        self._append_log("[SERVER] Stopped.")
        self.statusBar().showMessage("Server stopped.")

    def _on_server_listening(self):
        self.statusBar().showMessage("Server listening... Waiting for connection.")

    def _on_server_finished(self, success: bool, message: str):
        self.btn_start_server.setEnabled(True)
        self.btn_stop_server.setEnabled(False)
        if success:
            self.statusBar().showMessage(f"✓ {message}")
        else:
            self.statusBar().showMessage(f"✗ {message}")

    # ================================================================
    # Client Actions
    # ================================================================
    def _browse_save_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Save Directory")
        if dir_path:
            self.save_dir = dir_path
            self.save_dir_input.setText(dir_path)

    def _browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if file_path:
            self.selected_file = file_path
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.file_label.setText(f"{os.path.basename(file_path)} ({size_mb:.2f} MB)")
            self.file_label.setStyleSheet("color: #1e66f5; font-weight: bold;")
            self.btn_send.setEnabled(True)

    def _send_file(self):
        if not self.selected_file:
            QMessageBox.warning(self, "No File", "Please select a file first.")
            return

        host = self.ip_input.text().strip()
        port = self.port_input.value()

        # Read attack toggles from Test Scenarios tab
        simulate_tampering = self.chk_tampering.isChecked()
        simulate_broken_pq = self.chk_broken_pq.isChecked()
        simulate_replay = self.chk_replay.isChecked()

        if simulate_tampering:
            self._append_log("⚠ ATTACK ENABLED: Ciphertext Tampering (Scenario 3)")
        if simulate_broken_pq:
            self._append_log("⚠ ATTACK ENABLED: Broken PQ Algorithm (Scenario 4)")
        if simulate_replay:
            self._append_log("⚠ ATTACK ENABLED: Replay Attack (Scenario 6)")

        self.client_worker = ClientWorker(
            host, port, self.selected_file,
            simulate_tampering=simulate_tampering,
            simulate_broken_pq=simulate_broken_pq,
            simulate_replay=simulate_replay,
            save_encrypted=self.chk_save_encrypted.isChecked(),
        )
        self.client_worker.log_signal.connect(self._append_log)
        self.client_worker.progress_signal.connect(self._update_progress)
        self.client_worker.finished_signal.connect(self._on_client_finished)
        self.client_worker.start()

        self.btn_send.setEnabled(False)
        self.statusBar().showMessage("Encrypting and sending file...")

    def _on_client_finished(self, success: bool, message: str):
        self.btn_send.setEnabled(True)
        if success:
            self.statusBar().showMessage(f"✓ {message}")
        else:
            self.statusBar().showMessage(f"✗ {message}")

    # ================================================================
    # Benchmark Action
    # ================================================================
    def _run_benchmark(self):
        iterations = self.bench_iterations.value()
        self.benchmark_worker = BenchmarkWorker(iterations)
        self.benchmark_worker.log_signal.connect(self._append_log)
        self.benchmark_worker.progress_signal.connect(self._update_progress)
        self.benchmark_worker.finished_signal.connect(self._on_benchmark_finished)
        self.benchmark_worker.start()

        self.btn_benchmark.setEnabled(False)
        self.statusBar().showMessage(f"Running {iterations}-iteration benchmark...")

    def _on_benchmark_finished(self, results: dict):
        self.btn_benchmark.setEnabled(True)
        self.statusBar().showMessage(
            f"Benchmark complete — Hybrid avg: {results['hybrid_avg_ms']:.4f} ms "
            f"(+{results['overhead_pct']:.1f}% over X25519-only)"
        )

    # ================================================================
    # UI Helpers
    # ================================================================
    def _append_log(self, text: str):
        """Append a log line with color-coded prefixes."""
        if "✗" in text or "FAILED" in text or "ERROR" in text.upper():
            color = "#e64553"
        elif "✓" in text or "SUCCESS" in text.upper() or "Verified" in text:
            color = "#40a02b"
        elif "⚠" in text or "ATTACK" in text or "SIMULATING" in text:
            color = "#df8e1d"
        elif "[BENCHMARK]" in text:
            color = "#8839ef"
        else:
            color = "#cdd6f4"

        self.log_view.append(f'<span style="color:{color};">{text}</span>')
        # Auto-scroll to bottom
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _update_progress(self, current: int, total: int):
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)
        else:
            self.progress_bar.setValue(0)


# ================================================================
# Entry Point
# ================================================================
def main():
    app = QApplication(sys.argv)

    # Apply global stylesheet
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f5f5f5;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #ccc;
            border-radius: 6px;
            margin-top: 10px;
            padding-top: 14px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
        }
        QLineEdit, QSpinBox {
            padding: 4px 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            background: white;
        }
        QCheckBox {
            font-size: 12px;
            padding: 4px;
        }
        QTabWidget::pane {
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        QTabBar::tab {
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #1e66f5;
            color: white;
            border-radius: 4px 4px 0 0;
        }
        QProgressBar {
            border: 1px solid #ccc;
            border-radius: 4px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #1e66f5;
            border-radius: 3px;
        }
    """)

    window = HybridKEMApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
