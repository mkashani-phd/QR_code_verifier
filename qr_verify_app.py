import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import cv2
import numpy as np
from PIL import Image

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


def normalize_public_key_text(text: str) -> str:
    """
    Accepts:
      - ssh-ed25519 AAAA... [comment]
      - known_hosts lines: host ssh-ed25519 AAAA... comment
      - PEM public key blocks
    Returns:
      - Clean OpenSSH public key line, or original PEM.
    """
    t = text.strip()
    if not t:
        return t

    # private key guard
    if "BEGIN OPENSSH PRIVATE KEY" in t or "BEGIN PRIVATE KEY" in t:
        raise ValueError(
            "You pasted a PRIVATE key. The verifier needs a PUBLIC key.\n\n"
            "Extract public key with:\n"
            "  ssh-keygen -y -f <private_key>\n"
            "and paste the line that starts with ssh-ed25519/ssh-rsa/..."
        )

    # PEM stays as-is
    if "BEGIN PUBLIC KEY" in t or t.startswith("-----BEGIN"):
        return t

    tokens = t.split()
    ssh_types = (
        "ssh-ed25519",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
    )

    for i, tok in enumerate(tokens):
        if tok in ssh_types:
            if i + 1 >= len(tokens):
                raise ValueError("SSH public key is missing its base64 data.")
            out = tokens[i:i+2]
            if i + 2 < len(tokens):
                out.append(" ".join(tokens[i+2:]))
            return " ".join(out)

    return t


def verify_with_public_key_text(pub_key_text: str, message_text: str, sig_bytes: bytes) -> None:
    """
    Verifies signature over message_text (UTF-8 bytes).
    Supports:
      - OpenSSH public key lines: ssh-ed25519 / ssh-rsa / ecdsa-sha2-* / sk-* / certs
      - PEM public keys: -----BEGIN PUBLIC KEY-----
    """
    key_text = normalize_public_key_text(pub_key_text).strip()
    if not key_text:
        raise ValueError("Public key is empty.")

    msg_bytes = message_text.encode("utf-8")

    # OpenSSH public key line
    if key_text.startswith("ssh-") or key_text.startswith("ecdsa-sha2-") or key_text.startswith("sk-"):
        pub = serialization.load_ssh_public_key(key_text.encode("utf-8"))
        pub.verify(sig_bytes, msg_bytes)
        return

    # PEM public key
    pub = serialization.load_pem_public_key(key_text.encode("utf-8"))

    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(
            sig_bytes,
            msg_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return

    if isinstance(pub, ec.EllipticCurvePublicKey):
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        pub.verify(sig_bytes, msg_bytes, _ec.ECDSA(hashes.SHA256()))
        return

    raise ValueError("Unsupported public key type for verification.")


def parse_message_qr_json(qr_text: str) -> Tuple[str, str, bytes]:
    """
    Expected QR JSON:
      {"k":"<kid>","m":"<message>","s":"<base64url signature>"}
    """
    try:
        obj = json.loads(qr_text)
    except Exception:
        raise ValueError("QR does not contain valid JSON.")

    if not isinstance(obj, dict):
        raise ValueError("QR JSON must be an object.")
    for field in ("k", "m", "s"):
        if field not in obj:
            raise ValueError(f"QR JSON missing field '{field}'.")

    kid = str(obj["k"]).strip()
    msg = str(obj["m"])
    sig_b64 = str(obj["s"]).strip()

    if not kid:
        raise ValueError("Field 'k' (kid) is empty.")
    if not sig_b64:
        raise ValueError("Field 's' (signature) is empty.")

    sig = b64url_decode(sig_b64)
    return kid, msg, sig


def decode_qr_from_image_robust(path: str) -> str:
    """
    Robust QR decoding for file images (macOS friendly).
    - Load with PIL (handles HEIC/odd PNGs better than cv2.imread)
    - Try raw/grayscale/adaptive threshold/otsu + upscales
    """
    pil = Image.open(path).convert("RGB")
    rgb = np.array(pil)
    bgr0 = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()

    def try_decode(img_bgr: np.ndarray) -> str:
        decoded, _, _ = detector.detectAndDecode(img_bgr)
        if decoded:
            return decoded.strip()
        try:
            ok, infos, _, _ = detector.detectAndDecodeMulti(img_bgr)
            if ok and infos:
                for s in infos:
                    if s:
                        return s.strip()
        except Exception:
            pass
        return ""

    gray0 = cv2.cvtColor(bgr0, cv2.COLOR_BGR2GRAY)

    candidates = [
        bgr0,
        cv2.cvtColor(gray0, cv2.COLOR_GRAY2BGR),
        cv2.cvtColor(
            cv2.adaptiveThreshold(gray0, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5),
            cv2.COLOR_GRAY2BGR
        ),
        cv2.cvtColor(
            cv2.threshold(gray0, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
            cv2.COLOR_GRAY2BGR
        ),
    ]

    for base in candidates:
        for s in [1.0, 1.5, 2.0, 3.0]:
            img = base if s == 1.0 else cv2.resize(base, None, fx=s, fy=s, interpolation=cv2.INTER_CUBIC)
            decoded = try_decode(img)
            if decoded:
                return decoded

    raise ValueError("No QR code detected in this image (tried multiple preprocess + scales).")


# -----------------------------
# Public key registry
# -----------------------------
@dataclass
class PubKeyEntry:
    kid: str
    pub_pem: str  # can store PEM or ssh-* public key line


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
        pub_norm = normalize_public_key_text(pub_pem)
        self.keys[kid] = PubKeyEntry(kid=kid, pub_pem=pub_norm)
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
        self._last_msg: str = ""
        self._last_sig: Optional[bytes] = None

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

        btns = QHBoxLayout()
        layout.addLayout(btns)

        self.btn_webcam = QPushButton("Scan QR (Webcam)")
        self.btn_webcam.clicked.connect(self.on_scan_webcam)
        btns.addWidget(self.btn_webcam)

        self.btn_file = QPushButton("Load QR Image File…")
        self.btn_file.clicked.connect(self.on_load_qr_image)
        btns.addWidget(self.btn_file)

        btns.addStretch(1)

        self.status = QLabel("Load/scan a QR to verify.")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.status)

        msg_box = QGroupBox("Message")
        layout.addWidget(msg_box)
        mv = QV(msg_box)

        self.big_message = QTextEdit()
        self.big_message.setReadOnly(True)
        self.big_message.setStyleSheet("font-size: 22px;")
        self.big_message.setPlaceholderText("Verified message will appear here.")
        self.big_message.setFixedHeight(220)
        mv.addWidget(self.big_message)

        self.key_box = QGroupBox("Public Key Needed")
        layout.addWidget(self.key_box)
        kv = QV(self.key_box)

        self.pubkey_pem = QTextEdit()
        self.pubkey_pem.setPlaceholderText(
            "Public key for this kid was not found in public_keys.json.\n"
            "Paste PUBLIC KEY here (ssh-ed25519/ssh-rsa/... or PEM public key), then click Verify + Save.\n\n"
            "Tip: If you only have the private key, get the public key with:\n"
            "  ssh-keygen -y -f <private_key>"
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

    def on_scan_webcam(self):
        dlg = QRScannerDialog(self)
        if dlg.exec() == QDialog.Accepted:
            s = dlg.get_result()
            if s:
                self._handle_qr_string(s)

    def on_load_qr_image(self):
        try:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select QR image", "",
                "Images (*.png *.jpg *.jpeg *.bmp *.tif *.tiff *.heic *.heif);;All files (*)"
            )
            if not path:
                return
            decoded = decode_qr_from_image_robust(path)
            self._handle_qr_string(decoded)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _handle_qr_string(self, qr: str):
        self.key_box.setVisible(False)
        self.pubkey_pem.clear()
        self.big_message.clear()
        self.status.setText("Parsing…")

        try:
            kid, msg, sig = parse_message_qr_json(qr)

            self._last_kid = kid
            self._last_msg = msg
            self._last_sig = sig

            entry = self.registry.get(kid)
            if not entry:
                self.status.setText(f"⚠️ No stored public key for kid={kid}. Paste it below.")
                self.key_box.setVisible(True)
                QMessageBox.warning(
                    self,
                    "Public key missing",
                    f"No public key stored for kid={kid}.\n\n"
                    f"Paste the PUBLIC KEY, then click Verify + Save."
                )
                self.big_message.setPlainText(msg)  # untrusted until verified
                return

            verify_with_public_key_text(entry.pub_pem, msg, sig)

            self.big_message.setPlainText(msg)
            self.status.setText(f"✅ VALID signature (kid={kid})")

        except InvalidSignature:
            self.status.setText("❌ INVALID signature")
            QMessageBox.critical(self, "Invalid", "Signature is INVALID.")
        except Exception as e:
            self.status.setText(f"❌ {e}")
            QMessageBox.critical(self, "Error", str(e))

    def on_verify_with_pasted_key(self):
        try:
            if not self._last_kid or self._last_sig is None:
                raise ValueError("No QR loaded yet. Scan/load a QR first.")

            key_text_raw = self.pubkey_pem.toPlainText().strip()
            key_text = normalize_public_key_text(key_text_raw)
            if not key_text:
                raise ValueError("Paste a PUBLIC key first.")

            verify_with_public_key_text(key_text, self._last_msg, self._last_sig)

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

            key_text_raw = self.pubkey_pem.toPlainText().strip()
            key_text = normalize_public_key_text(key_text_raw)
            if not key_text:
                raise ValueError("Public key text is empty.")

            # sanity-load
            if key_text.startswith("ssh-") or key_text.startswith("ecdsa-sha2-") or key_text.startswith("sk-"):
                serialization.load_ssh_public_key(key_text.encode("utf-8"))
            else:
                serialization.load_pem_public_key(key_text.encode("utf-8"))

            self.registry.upsert(self._last_kid, key_text)
            QMessageBox.information(self, "Saved", f"Saved key for kid={self._last_kid} to:\n{PUBREG_PATH}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

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