import os
import json
import base64
import hashlib
from typing import Optional, List, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QMessageBox, QFileDialog,
    QGroupBox, QLineEdit, QComboBox
)

import qrcode
from PIL import Image

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ed25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


# -----------------------------
# Config
# -----------------------------
APP_DIR = os.path.abspath(os.path.dirname(__file__))
KEYSTORE_DIR = os.path.join(APP_DIR, "keystore")
os.makedirs(KEYSTORE_DIR, exist_ok=True)

# New QR structure: JSON only
# {"k":"<kid>","m":"<message>","s":"<base64url signature>"}


# -----------------------------
# Helpers
# -----------------------------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def pil_to_qpixmap(img: Image.Image) -> QPixmap:
    img = img.convert("RGBA")
    data = img.tobytes("raw", "RGBA")
    qimg = QImage(data, img.width, img.height, QImage.Format_RGBA8888)
    return QPixmap.fromImage(qimg)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def make_message_qr_json(kid: str, message: str, sig: bytes) -> str:
    """
    QR JSON format (fixed):
      {"k":"<kid>","m":"<message>","s":"<base64url signature>"}
    """
    obj = {"k": kid, "m": message, "s": b64url_encode(sig)}
    # separators removes whitespace so QR is smaller
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _extract_kid_from_filename(filename: str) -> Optional[str]:
    """
    kid is everything before '_private' (case-insensitive)
    Moh_private.key -> kid=Moh
    """
    lower = filename.lower()
    if "_private" not in lower:
        return None
    idx = lower.index("_private")
    kid = filename[:idx].strip()
    return kid if kid else None


def _file_looks_like_private_key(path: str) -> bool:
    """Only list files that actually look like private keys."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)

        if b"BEGIN OPENSSH PRIVATE KEY" in head:
            return True
        if b"BEGIN PRIVATE KEY" in head or b"BEGIN RSA PRIVATE KEY" in head:
            return True

        return False
    except Exception:
        return False


def list_keystore_keys(keystore_dir: str) -> List[Tuple[str, str]]:
    """
    Returns list of (kid, filepath) for private keys found.
    Accepts .key / .pem but only if the content looks like a private key.
    """
    out: List[Tuple[str, str]] = []
    for fn in sorted(os.listdir(keystore_dir)):
        path = os.path.join(keystore_dir, fn)
        if not os.path.isfile(path):
            continue
        if not (fn.lower().endswith(".key") or fn.lower().endswith(".pem")):
            continue

        kid = _extract_kid_from_filename(fn)
        if not kid:
            continue

        if not _file_looks_like_private_key(path):
            continue

        out.append((kid, path))

    # Dedup by kid
    seen = set()
    dedup = []
    for kid, path in out:
        if kid in seen:
            continue
        seen.add(kid)
        dedup.append((kid, path))
    return dedup


def _key_debug_hint(path: str) -> str:
    """Small diagnostic snippet to show in error dialogs."""
    try:
        with open(path, "rb") as f:
            lines = f.read().splitlines()
        first = lines[0].decode("utf-8", "replace") if lines else "(empty file)"
        second = lines[1].decode("utf-8", "replace")[:80] if len(lines) > 1 else ""
        return f"First line: {first}\nSecond line (start): {second}"
    except Exception as e:
        return f"(Could not read file for debug: {e})"


def load_private_key_any(path: str):
    """
    Supports:
      - OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----)
      - PEM private key (-----BEGIN PRIVATE KEY----- or RSA PRIVATE KEY)
    """
    with open(path, "rb") as f:
        data = f.read()

    # Common mistake: user selected an SSH PUBLIC key file
    if data.lstrip().startswith(b"ssh-") or data.lstrip().startswith(b"ecdsa-sha2-") or data.lstrip().startswith(b"sk-"):
        raise ValueError(
            "This file looks like an SSH PUBLIC key (starts with 'ssh-...' / 'ecdsa-sha2-...').\n"
            "Select the PRIVATE key file that begins with:\n"
            "  -----BEGIN OPENSSH PRIVATE KEY-----\n\n"
            + _key_debug_hint(path)
        )

    # OpenSSH private key
    if b"BEGIN OPENSSH PRIVATE KEY" in data:
        try:
            return serialization.load_ssh_private_key(data, password=None)
        except Exception as e:
            raise ValueError(
                "Failed to load OpenSSH PRIVATE key.\n\n"
                "Most common causes:\n"
                "  • The file is corrupted (e.g., contains '...' or non-base64 characters)\n"
                "  • The file was copy/pasted and changed\n\n"
                "Try regenerating it with:\n"
                "  ssh-keygen -t ed25519 -f keystore/Moh_private.key -N \"\"\n\n"
                f"Underlying error: {e}\n\n"
                + _key_debug_hint(path)
            )

    # PEM private key
    if b"BEGIN PRIVATE KEY" in data or b"BEGIN RSA PRIVATE KEY" in data:
        return serialization.load_pem_private_key(data, password=None)

    raise ValueError(
        "Unrecognized key format.\n"
        "Expected an OpenSSH private key or PEM private key.\n\n"
        + _key_debug_hint(path)
    )


def sign_any(privkey, message_bytes: bytes) -> Tuple[str, bytes]:
    """
    Returns (alg, signature_bytes). We do NOT put alg into QR anymore.
    The verifier infers algorithm from the PUBLIC key type.
    """
    if isinstance(privkey, ed25519.Ed25519PrivateKey):
        return "Ed25519", privkey.sign(message_bytes)

    if isinstance(privkey, RSAPrivateKey):
        sig = privkey.sign(
            message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return "RSA-PSS-SHA256", sig

    raise ValueError(f"Unsupported private key type: {type(privkey)}")


# -----------------------------
# UI
# -----------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR Signer (Simple)")
        self.resize(820, 620)

        self._qr_pil: Optional[Image.Image] = None
        self._keys: List[Tuple[str, str]] = []

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        self.tab_sign = QWidget()
        self.tab_integrity = QWidget()
        tabs.addTab(self.tab_sign, "Sign")
        tabs.addTab(self.tab_integrity, "App Integrity")

        self._build_sign_tab()
        self._build_integrity_tab()
        self._refresh_integrity()
        self.reload_keys()

    # -------- Sign tab --------
    def _build_sign_tab(self):
        layout = QVBoxLayout(self.tab_sign)

        top = QHBoxLayout()
        layout.addLayout(top)

        top.addWidget(QLabel("Private key:"))
        self.key_combo = QComboBox()
        self.key_combo.setMinimumWidth(260)
        top.addWidget(self.key_combo, 1)

        self.btn_reload = QPushButton("Reload keystore")
        self.btn_reload.clicked.connect(self.reload_keys)
        top.addWidget(self.btn_reload)

        layout.addWidget(QLabel("Message:"))
        self.msg_in = QTextEdit()
        self.msg_in.setPlaceholderText("Type message here…")
        self.msg_in.setFixedHeight(160)
        layout.addWidget(self.msg_in)

        row = QHBoxLayout()
        layout.addLayout(row)

        self.btn_sign = QPushButton("Sign → Generate QR")
        self.btn_sign.clicked.connect(self.on_sign)
        row.addWidget(self.btn_sign)
        row.addStretch(1)

        self.status = QLabel("")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.status)

        qr_row = QHBoxLayout()
        layout.addLayout(qr_row)

        self.qr_img = QLabel("(QR preview)")
        self.qr_img.setAlignment(Qt.AlignCenter)
        self.qr_img.setMinimumSize(320, 320)
        qr_row.addWidget(self.qr_img, 1)

        right = QVBoxLayout()
        qr_row.addLayout(right, 1)

        right.addWidget(QLabel("QR JSON:"))
        self.qr_str_out = QTextEdit()
        self.qr_str_out.setReadOnly(True)
        self.qr_str_out.setFixedHeight(170)
        right.addWidget(self.qr_str_out)

        self.btn_copy = QPushButton("Copy QR JSON")
        self.btn_copy.clicked.connect(self.on_copy)
        right.addWidget(self.btn_copy)

        self.btn_save = QPushButton("Save QR PNG…")
        self.btn_save.clicked.connect(self.on_save_png)
        right.addWidget(self.btn_save)

        right.addStretch(1)

    def reload_keys(self):
        self._keys = list_keystore_keys(KEYSTORE_DIR)
        self.key_combo.clear()

        if not self._keys:
            self.key_combo.addItem("(no private keys found in ./keystore)", None)
            self.status.setText(
                f"⚠️ No private keys found in: {KEYSTORE_DIR}\n"
                f"Expected filenames like: Moh_private.key (contains OPENSSH PRIVATE KEY)\n"
                f"Generate one with:\n"
                f"  ssh-keygen -t ed25519 -f {os.path.join(KEYSTORE_DIR, 'Moh_private.key')} -N \"\""
            )
            return

        for kid, path in self._keys:
            self.key_combo.addItem(f"{kid}", path)

        self.status.setText(f"Loaded {len(self._keys)} private key(s) from: {KEYSTORE_DIR}")

    def on_sign(self):
        try:
            path = self.key_combo.currentData()
            if not path:
                raise ValueError("No private key selected (keystore is empty).")

            msg = self.msg_in.toPlainText()
            if not msg.strip():
                raise ValueError("Message is empty.")

            filename = os.path.basename(path)
            kid = _extract_kid_from_filename(filename)
            if not kid:
                raise ValueError(f"Could not derive kid from filename: {filename}")

            priv = load_private_key_any(path)

            # NEW RULE: sign ONLY the message bytes
            msg_bytes = msg.encode("utf-8")
            alg, sig = sign_any(priv, msg_bytes)

            # NEW QR: pure JSON {"k","m","s"}
            qr_str = make_message_qr_json(kid, msg, sig)
            self.qr_str_out.setPlainText(qr_str)

            img = qrcode.make(qr_str).resize((320, 320))
            self._qr_pil = img
            self.qr_img.setPixmap(pil_to_qpixmap(img))

            self.status.setText(f"✅ Signed with kid={kid} ({alg})")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_copy(self):
        s = self.qr_str_out.toPlainText().strip()
        if not s:
            QMessageBox.warning(self, "Copy", "No QR JSON to copy.")
            return
        QApplication.clipboard().setText(s)
        QMessageBox.information(self, "Copy", "Copied QR JSON.")

    def on_save_png(self):
        if self._qr_pil is None:
            QMessageBox.warning(self, "Save", "Generate a QR first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save QR as PNG", "signed_message_qr.png", "PNG (*.png)")
        if not path:
            return
        self._qr_pil.save(path, format="PNG")
        QMessageBox.information(self, "Saved", f"Saved to:\n{path}")

    # -------- Integrity tab --------
    def _build_integrity_tab(self):
        layout = QVBoxLayout(self.tab_integrity)

        box = QGroupBox("App Integrity (SHA-256 of this .py file)")
        layout.addWidget(box)

        v = QVBoxLayout(box)

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