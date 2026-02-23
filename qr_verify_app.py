import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import cv2

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit, QMessageBox, QFileDialog,
    QGroupBox, QVBoxLayout as QV, QDialog
)

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


# -----------------------------
# Config
# -----------------------------
APP_DIR = os.path.abspath(os.path.dirname(__file__))
PUBREG_PATH = os.path.join(APP_DIR, "public_keys.json")
MSG_QR_PREFIX = "M1"  # M1.<kid>.<payload_b64url>.<sig_b64url>


# -----------------------------
# Helpers
# -----------------------------
def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cv_bgr_to_qpixmap(frame_bgr) -> QPixmap:
    rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
    h, w, ch = rgb.shape
    bytes_per_line = ch * w
    qimg = QImage(rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)
    return QPixmap.fromImage(qimg)


def parse_message_qr_string(qr: str) -> Tuple[str, dict, bytes, bytes]:
    # M1.kid.payload_b64.sig_b64
    parts = qr.strip().split(".")
    if len(parts) != 4 or parts[0] != MSG_QR_PREFIX:
        raise ValueError("QR must be: M1.<kid>.<payload_b64url>.<sig_b64url>")
    kid = parts[1]
    payload_b = b64url_decode(parts[2])
    sig_b = b64url_decode(parts[3])
    payload_obj = json.loads(payload_b.decode("utf-8"))
    return kid, payload_obj, payload_b, sig_b


def verify_with_public_key_pem(pub_pem_text: str, payload_bytes: bytes, sig_bytes: bytes) -> None:
    pub = serialization.load_pem_public_key(pub_pem_text.encode("utf-8"))
    pub.verify(
        sig_bytes,
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


# -----------------------------
# Public key registry
# -----------------------------
@dataclass
class PubKeyEntry:
    kid: str
    pub_pem: str


class PublicKeyRegistry:
    def __init__(self, path: str):
        self.path = path
        self.keys: Dict[str, PubKeyEntry] = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.keys = {}
            return
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = {}
        for item in data.get("keys", []):
            out[item["kid"]] = PubKeyEntry(kid=item["kid"], pub_pem=item["pub_pem"])
        self.keys = out

    def save(self):
        data = {"keys": []}
        for kid, entry in sorted(self.keys.items(), key=lambda kv: kv[0]):
            data["keys"].append({"kid": entry.kid, "pub_pem": entry.pub_pem})
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def get(self, kid: str) -> Optional[PubKeyEntry]:
        return self.keys.get(kid)

    def upsert(self, kid: str, pub_pem: str):
        self.keys[kid] = PubKeyEntry(kid=kid, pub_pem=pub_pem)
        self.save()


# -----------------------------
# Webcam QR scanner dialog
# -----------------------------
class QRScannerDialog(QDialog):
    def __init__(self, parent=None, camera_index: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Scan QR (Webcam)")
        self.resize(820, 620)

        self._cap = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

        self._detector = cv2.QRCodeDetector()
        self._result: Optional[str] = None

        v = QVBoxLayout(self)

        self.video_label = QLabel("Starting camera…")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setMinimumHeight(480)
        v.addWidget(self.video_label, 1)

        self.status = QLabel("Scanning…")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.status)

        btns = QHBoxLayout()
        v.addLayout(btns)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        btns.addWidget(self.btn_cancel)

        self.start(camera_index)

    def start(self, camera_index: int = 0):
        self._cap = cv2.VideoCapture(camera_index)
        if not self._cap.isOpened():
            self.status.setText("❌ Could not open camera.")
            return
        self._timer.start(30)

    def stop(self):
        if self._timer.isActive():
            self._timer.stop()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

    def _tick(self):
        if self._cap is None:
            return
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return

        try:
            retval, decoded_info, points, _ = self._detector.detectAndDecodeMulti(frame)
        except Exception:
            retval, decoded_info, points = False, [], None

        if points is not None and len(points) > 0:
            for quad in points:
                quad = quad.astype(int)
                cv2.polylines(frame, [quad], True, (0, 255, 0), 2)

        pix = cv_bgr_to_qpixmap(frame)
        self.video_label.setPixmap(pix.scaled(
            self.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))

        if retval and decoded_info:
            decoded = next((s for s in decoded_info if s), None)
            if decoded:
                self._result = decoded.strip()
                self.status.setText("✅ QR detected. Closing…")
                self._timer.stop()
                QTimer.singleShot(150, self.accept)

    def get_result(self) -> Optional[str]:
        return self._result

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)


# -----------------------------
# Main UI
# -----------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR Verifier (Simple)")
        self.resize(850, 620)

        self.registry = PublicKeyRegistry(PUBREG_PATH)

        self._last_kid: Optional[str] = None
        self._last_payload_b: Optional[bytes] = None
        self._last_sig_b: Optional[bytes] = None
        self._last_msg: str = ""

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        self.tab_verify = QWidget()
        self.tab_integrity = QWidget()
        tabs.addTab(self.tab_verify, "Verify")
        tabs.addTab(self.tab_integrity, "App Integrity")

        self._build_verify_tab()
        self._build_integrity_tab()
        self._refresh_integrity()

    def _build_verify_tab(self):
        layout = QVBoxLayout(self.tab_verify)

        # Top buttons (only two)
        btns = QHBoxLayout()
        layout.addLayout(btns)

        self.btn_webcam = QPushButton("Scan QR (Webcam)")
        self.btn_webcam.clicked.connect(self.on_scan_webcam)
        btns.addWidget(self.btn_webcam)

        self.btn_file = QPushButton("Load QR Image File…")
        self.btn_file.clicked.connect(self.on_load_qr_image)
        btns.addWidget(self.btn_file)

        btns.addStretch(1)

        # Status
        self.status = QLabel("Load/scan a QR to verify.")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.status)

        # Big message output
        msg_box = QGroupBox("Message")
        layout.addWidget(msg_box)
        mv = QV(msg_box)

        self.big_message = QTextEdit()
        self.big_message.setReadOnly(True)
        self.big_message.setStyleSheet("font-size: 22px;")
        self.big_message.setPlaceholderText("Verified message will appear here.")
        self.big_message.setFixedHeight(220)
        mv.addWidget(self.big_message)

        # Public key fallback (hidden unless needed)
        self.key_box = QGroupBox("Public Key Needed")
        layout.addWidget(self.key_box)
        kv = QV(self.key_box)

        self.pubkey_pem = QTextEdit()
        self.pubkey_pem.setPlaceholderText(
            "Public key for this kid was not found in public_keys.json.\n"
            "Paste PUBLIC KEY PEM here, then click Verify + Save."
        )
        self.pubkey_pem.setFixedHeight(140)
        kv.addWidget(self.pubkey_pem)

        key_btns = QHBoxLayout()
        kv.addLayout(key_btns)

        self.btn_verify = QPushButton("Verify (with pasted key)")
        self.btn_verify.clicked.connect(self.on_verify_with_pasted_key)
        key_btns.addWidget(self.btn_verify)

        self.btn_save_key = QPushButton("Save Key for this kid")
        self.btn_save_key.clicked.connect(self.on_save_key_for_kid)
        key_btns.addWidget(self.btn_save_key)

        key_btns.addStretch(1)

        self.key_box.setVisible(False)

        layout.addStretch(1)

    # ---- Main flows ----
    def on_scan_webcam(self):
        dlg = QRScannerDialog(self)
        if dlg.exec() == QDialog.Accepted:
            s = dlg.get_result()
            if s:
                self._handle_qr_string(s)

    def on_load_qr_image(self):
        try:
            path, _ = QFileDialog.getOpenFileName(self, "Select QR image", "", "Images (*.png *.jpg *.jpeg *.bmp);;All files (*)")
            if not path:
                return
            img = cv2.imread(path)
            if img is None:
                raise ValueError("Could not read image.")
            detector = cv2.QRCodeDetector()
            decoded, points, _ = detector.detectAndDecode(img)
            if not decoded:
                raise ValueError("No QR code detected in this image.")
            self._handle_qr_string(decoded.strip())
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _handle_qr_string(self, qr: str):
        # Reset UI
        self.key_box.setVisible(False)
        self.pubkey_pem.clear()
        self.big_message.clear()
        self.status.setText("Parsing…")

        try:
            kid, payload_obj, payload_b, sig_b = parse_message_qr_string(qr)

            self._last_kid = kid
            self._last_payload_b = payload_b
            self._last_sig_b = sig_b
            self._last_msg = str(payload_obj.get("msg", ""))

            # Try to verify using saved key
            entry = self.registry.get(kid)
            if not entry:
                # Ask for public key
                self.status.setText(f"⚠️ No stored public key for kid={kid}. Paste it below.")
                self.key_box.setVisible(True)
                QMessageBox.warning(self, "Public key missing",
                                    f"No public key stored for kid={kid}.\n\n"
                                    f"Paste the PUBLIC KEY PEM, then click Verify + Save.")
                # Still show message (untrusted until verified)
                self.big_message.setPlainText(self._last_msg)
                return

            verify_with_public_key_pem(entry.pub_pem, payload_b, sig_b)

            self.big_message.setPlainText(self._last_msg)
            self.status.setText(f"✅ VALID signature (kid={kid})")

        except InvalidSignature:
            self.status.setText("❌ INVALID signature")
            QMessageBox.critical(self, "Invalid", "Signature is INVALID.")
        except Exception as e:
            self.status.setText(f"❌ {e}")
            QMessageBox.critical(self, "Error", str(e))

    def on_verify_with_pasted_key(self):
        try:
            if not self._last_kid or self._last_payload_b is None or self._last_sig_b is None:
                raise ValueError("No QR loaded yet. Scan/load a QR first.")

            pem = self.pubkey_pem.toPlainText().strip()
            if not pem:
                raise ValueError("Paste a PUBLIC KEY PEM first.")

            # sanity-load + verify
            verify_with_public_key_pem(pem, self._last_payload_b, self._last_sig_b)

            self.big_message.setPlainText(self._last_msg)
            self.status.setText(f"✅ VALID signature (kid={self._last_kid}) — key provided manually")

        except InvalidSignature:
            self.status.setText("❌ INVALID signature")
            QMessageBox.critical(self, "Invalid", "Signature is INVALID.")
        except Exception as e:
            self.status.setText(f"❌ {e}")
            QMessageBox.critical(self, "Error", str(e))

    def on_save_key_for_kid(self):
        try:
            if not self._last_kid:
                raise ValueError("No kid available. Scan/load a QR first.")

            pem = self.pubkey_pem.toPlainText().strip()
            if not pem:
                raise ValueError("Public key PEM is empty.")

            # sanity check
            serialization.load_pem_public_key(pem.encode("utf-8"))

            self.registry.upsert(self._last_kid, pem)
            QMessageBox.information(self, "Saved", f"Saved key for kid={self._last_kid} to:\n{PUBREG_PATH}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # -------- Integrity tab --------
    def _build_integrity_tab(self):
        layout = QVBoxLayout(self.tab_integrity)

        box = QGroupBox("App Integrity (SHA-256 of this .py file)")
        layout.addWidget(box)

        v = QV(box)

        self.integrity_path = QLineEdit()
        self.integrity_path.setReadOnly(True)
        v.addWidget(QLabel("File hashed:"))
        v.addWidget(self.integrity_path)

        self.integrity_hash = QTextEdit()
        self.integrity_hash.setReadOnly(True)
        self.integrity_hash.setFixedHeight(110)
        v.addWidget(QLabel("SHA-256:"))
        v.addWidget(self.integrity_hash)

        btns = QHBoxLayout()
        v.addLayout(btns)

        self.btn_rehash = QPushButton("Recompute")
        self.btn_rehash.clicked.connect(self._refresh_integrity)
        btns.addWidget(self.btn_rehash)

        self.btn_copy_hash = QPushButton("Copy Hash")
        self.btn_copy_hash.clicked.connect(self.on_copy_integrity_hash)
        btns.addWidget(self.btn_copy_hash)

        btns.addStretch(1)

    def _refresh_integrity(self):
        try:
            path = os.path.abspath(__file__)
            h = sha256_file(path)
            self.integrity_path.setText(path)
            self.integrity_hash.setPlainText(h)
        except Exception as e:
            self.integrity_hash.setPlainText(f"Error: {e}")

    def on_copy_integrity_hash(self):
        s = self.integrity_hash.toPlainText().strip()
        if not s:
            return
        QApplication.clipboard().setText(s)
        QMessageBox.information(self, "Copy", "Copied SHA-256 hash.")


def main():
    app = QApplication([])
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()