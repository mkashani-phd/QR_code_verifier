import os
import json
import base64
import time
import hashlib
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit, QMessageBox, QFileDialog,
    QGroupBox, QFormLayout, QScrollArea, QSizePolicy
)

import qrcode
from PIL import Image

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


SIG_ALG = "RSA-PSS-SHA256"
MSG_QR_PREFIX = "M1"   # M1.<kid>.<payload_b64url>.<sig_b64url>


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pil_to_qpixmap(img: Image.Image) -> QPixmap:
    img = img.convert("RGBA")
    data = img.tobytes("raw", "RGBA")
    qimg = QImage(data, img.width, img.height, QImage.Format_RGBA8888)
    return QPixmap.fromImage(qimg)


def load_private_key_pem_from_text(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)


def sign_with_private_key(privkey, payload_bytes: bytes) -> bytes:
    return privkey.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def make_message_qr_string(kid: str, payload_obj: dict, sig: bytes) -> str:
    payload_b = canonical_json_bytes(payload_obj)
    return f"{MSG_QR_PREFIX}.{kid}.{b64url_encode(payload_b)}.{b64url_encode(sig)}"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR Signer (RSA-PSS-SHA256)")
        self.resize(900, 650)  # smaller default

        self._qr_pil: Optional[Image.Image] = None

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        self.tab_sign = QWidget()
        self.tab_integrity = QWidget()

        tabs.addTab(self.tab_sign, "Sign → QR")
        tabs.addTab(self.tab_integrity, "App Integrity")

        self._build_sign_tab_compact()
        self._build_integrity_tab()
        self._refresh_integrity()

    # ---------------- Sign tab (compact + scroll) ----------------
    def _build_sign_tab_compact(self):
        # Make the whole sign tab scrollable so it always fits
        outer = QVBoxLayout(self.tab_sign)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        layout = QHBoxLayout(content)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        left = QVBoxLayout()
        right = QVBoxLayout()
        layout.addLayout(left, 2)
        layout.addLayout(right, 1)

        # Private key + kid
        key_box = QGroupBox("Signing Key")
        left.addWidget(key_box)
        form = QFormLayout(key_box)
        form.setLabelAlignment(Qt.AlignRight)

        self.kid_in = QLineEdit()
        self.kid_in.setPlaceholderText("kid (e.g., alice-key-1)")
        form.addRow("kid:", self.kid_in)

        self.privkey_pem_in = QTextEdit()
        self.privkey_pem_in.setPlaceholderText(
            "Paste PRIVATE KEY (PKCS8) PEM here..."
        )
        self.privkey_pem_in.setFixedHeight(120)  # smaller
        form.addRow("Private key:", self.privkey_pem_in)

        row = QHBoxLayout()
        self.btn_import_priv = QPushButton("Import PEM…")
        self.btn_import_priv.clicked.connect(self.on_import_private_key_file)
        row.addWidget(self.btn_import_priv)

        self.btn_clear_priv = QPushButton("Clear")
        self.btn_clear_priv.clicked.connect(lambda: self.privkey_pem_in.clear())
        row.addWidget(self.btn_clear_priv)
        form.addRow(row)

        # Message
        msg_box = QGroupBox("Message")
        left.addWidget(msg_box)
        mv = QVBoxLayout(msg_box)
        self.msg_in = QTextEdit()
        self.msg_in.setPlaceholderText("Message text (will be embedded in QR payload).")
        self.msg_in.setFixedHeight(120)  # smaller
        mv.addWidget(self.msg_in)

        # Sign button
        btn_row = QHBoxLayout()
        self.btn_sign = QPushButton("Sign → Generate QR")
        self.btn_sign.clicked.connect(self.on_sign_generate_qr)
        btn_row.addWidget(self.btn_sign)

        btn_row.addStretch(1)
        left.addLayout(btn_row)

        # Outputs (compact)
        out_box = QGroupBox("Outputs")
        left.addWidget(out_box, 1)
        ov = QVBoxLayout(out_box)
        ov.setSpacing(6)

        ov.addWidget(QLabel("Payload JSON:"))
        self.payload_out = QTextEdit()
        self.payload_out.setReadOnly(True)
        self.payload_out.setFixedHeight(120)
        ov.addWidget(self.payload_out)

        ov.addWidget(QLabel("Signature (b64url):"))
        self.sig_out = QTextEdit()
        self.sig_out.setReadOnly(True)
        self.sig_out.setFixedHeight(55)
        ov.addWidget(self.sig_out)

        ov.addWidget(QLabel("QR String:"))
        self.qr_str_out = QTextEdit()
        self.qr_str_out.setReadOnly(True)
        self.qr_str_out.setFixedHeight(90)
        ov.addWidget(self.qr_str_out)

        # Right: QR preview + actions (smaller)
        qr_box = QGroupBox("QR Preview")
        right.addWidget(qr_box, 1)
        qv = QVBoxLayout(qr_box)

        self.qr_img = QLabel("(QR preview)")
        self.qr_img.setAlignment(Qt.AlignCenter)
        self.qr_img.setMinimumHeight(240)
        self.qr_img.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        qv.addWidget(self.qr_img, 1)

        self.btn_copy_qr = QPushButton("Copy QR String")
        self.btn_copy_qr.clicked.connect(self.on_copy_qr_string)
        right.addWidget(self.btn_copy_qr)

        self.btn_save_png = QPushButton("Save QR PNG…")
        self.btn_save_png.clicked.connect(self.on_save_qr_png)
        right.addWidget(self.btn_save_png)

        right.addStretch(1)

    def on_import_private_key_file(self):
        try:
            path, _ = QFileDialog.getOpenFileName(self, "Select private key PEM", "", "PEM (*.pem *.key);;All files (*)")
            if not path:
                return
            with open(path, "r", encoding="utf-8") as f:
                self.privkey_pem_in.setPlainText(f.read())
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_sign_generate_qr(self):
        try:
            kid = self.kid_in.text().strip()
            if not kid:
                raise ValueError("kid is required.")

            pem = self.privkey_pem_in.toPlainText().strip()
            if not pem:
                raise ValueError("Private key PEM is required.")

            msg = self.msg_in.toPlainText()
            if not msg.strip():
                raise ValueError("Message is empty.")

            priv = load_private_key_pem_from_text(pem)

            payload = {
                "v": 1,
                "alg": SIG_ALG,
                "iat": int(time.time()),
                "msg": msg
            }
            payload_b = canonical_json_bytes(payload)

            sig = sign_with_private_key(priv, payload_b)
            qr_str = make_message_qr_string(kid, payload, sig)

            self.payload_out.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
            self.sig_out.setPlainText(b64url_encode(sig))
            self.qr_str_out.setPlainText(qr_str)

            # Smaller QR image to fit
            img = qrcode.make(qr_str).resize((320, 320))
            self._qr_pil = img
            self.qr_img.setPixmap(pil_to_qpixmap(img))

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_copy_qr_string(self):
        s = self.qr_str_out.toPlainText().strip()
        if not s:
            QMessageBox.warning(self, "Copy", "No QR string to copy.")
            return
        QApplication.clipboard().setText(s)
        QMessageBox.information(self, "Copy", "Copied QR string.")

    def on_save_qr_png(self):
        if self._qr_pil is None:
            QMessageBox.warning(self, "Save", "Generate a QR first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save QR as PNG", "signed_message_qr.png", "PNG (*.png)")
        if not path:
            return
        self._qr_pil.save(path, format="PNG")
        QMessageBox.information(self, "Saved", f"Saved to:\n{path}")

    # ---------------- Integrity tab ----------------
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