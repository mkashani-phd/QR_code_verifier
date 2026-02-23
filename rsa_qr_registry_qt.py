import os
import json
import base64
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit, QMessageBox, QFileDialog,
    QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog
)

import qrcode
from PIL import Image

import cv2

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# -----------------------------
# Config
# -----------------------------
APP_DIR = os.path.abspath(os.path.dirname(__file__))
REGISTRY_PATH = os.path.join(APP_DIR, "key_registry.json")
KEYSTORE_DIR = os.path.join(APP_DIR, "keystore")
os.makedirs(KEYSTORE_DIR, exist_ok=True)

SIG_ALG = "RSA-PSS-SHA256"

KEY_QR_PREFIX = "K1"   # key QR: K1.kid.name_b64.pub_der_b64

# Legacy message QR (kept for compatibility):
# M1.kid.payload_b64.sig_b64  (payload included msg/iat/alg)
MSG_QR_PREFIX_LEGACY = "M1"

# New message QR (your desired workflow):
# M2.kid.sig_b64             (message text is NOT in QR; user types it on verify)
MSG_QR_PREFIX_SIGONLY = "M2"


# -----------------------------
# Helpers
# -----------------------------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json_bytes(obj) -> bytes:
    # stable JSON for signing/verifying
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pil_to_qpixmap(img: Image.Image) -> QPixmap:
    img = img.convert("RGBA")
    data = img.tobytes("raw", "RGBA")
    qimg = QImage(data, img.width, img.height, QImage.Format_RGBA8888)
    return QPixmap.fromImage(qimg)


def cv_bgr_to_qpixmap(frame_bgr) -> QPixmap:
    rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
    h, w, ch = rgb.shape
    bytes_per_line = ch * w
    qimg = QImage(rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)
    return QPixmap.fromImage(qimg)


def rsa_public_key_to_der(pubkey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def rsa_public_key_from_der(der: bytes):
    return serialization.load_der_public_key(der)


def save_private_key_pem(privkey, path: str):
    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_private_key_pem_from_text(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)


def sign_with_private_key(privkey, payload_bytes: bytes) -> bytes:
    return privkey.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_with_public_key(pubkey, payload_bytes: bytes, sig: bytes) -> None:
    pubkey.verify(
        sig,
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


# -----------------------------
# Registry model
# -----------------------------
@dataclass
class KeyEntry:
    kid: str
    name: str
    pubkey_der_b64url: str
    privkey_path: Optional[str] = None  # if present, can sign in this app

    def public_key(self):
        return rsa_public_key_from_der(b64url_decode(self.pubkey_der_b64url))


class KeyRegistry:
    def __init__(self, path: str):
        self.path = path
        self.keys: Dict[str, KeyEntry] = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.keys = {}
            return
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        keys = {}
        for item in data.get("keys", []):
            entry = KeyEntry(
                kid=item["kid"],
                name=item.get("name", ""),
                pubkey_der_b64url=item["pubkey_der_b64url"],
                privkey_path=item.get("privkey_path")
            )
            keys[entry.kid] = entry
        self.keys = keys

    def save(self):
        data = {"keys": []}
        for kid, entry in sorted(self.keys.items(), key=lambda kv: kv[0]):
            data["keys"].append({
                "kid": entry.kid,
                "name": entry.name,
                "pubkey_der_b64url": entry.pubkey_der_b64url,
                "privkey_path": entry.privkey_path
            })
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def upsert(self, entry: KeyEntry):
        self.keys[entry.kid] = entry
        self.save()

    def delete(self, kid: str):
        if kid in self.keys:
            del self.keys[kid]
            self.save()

    def get(self, kid: str) -> Optional[KeyEntry]:
        return self.keys.get(kid)

    def list(self):
        return list(self.keys.values())


# -----------------------------
# QR format helpers
# -----------------------------
def make_key_qr_string(kid: str, name: str, pubkey_der: bytes) -> str:
    name_b64 = b64url_encode(name.encode("utf-8"))
    pub_b64 = b64url_encode(pubkey_der)
    return f"{KEY_QR_PREFIX}.{kid}.{name_b64}.{pub_b64}"


def parse_key_qr_string(qr: str) -> Tuple[str, str, bytes]:
    parts = qr.strip().split(".")
    if len(parts) != 4 or parts[0] != KEY_QR_PREFIX:
        raise ValueError("Key QR must be: K1.<kid>.<name_b64url>.<pubkey_der_b64url>")
    kid = parts[1]
    name = b64url_decode(parts[2]).decode("utf-8", errors="strict")
    pub_der = b64url_decode(parts[3])
    rsa_public_key_from_der(pub_der)  # sanity load
    return kid, name, pub_der


# Legacy (kept)
def make_message_qr_string_legacy(kid: str, payload_obj: dict, sig: bytes) -> str:
    payload_b = canonical_json_bytes(payload_obj)
    return f"{MSG_QR_PREFIX_LEGACY}.{kid}.{b64url_encode(payload_b)}.{b64url_encode(sig)}"


def parse_message_qr_string_legacy(qr: str):
    parts = qr.strip().split(".")
    if len(parts) != 4 or parts[0] != MSG_QR_PREFIX_LEGACY:
        raise ValueError("Message QR must be: M1.<kid>.<payload_b64url>.<sig_b64url>")
    kid = parts[1]
    payload_b = b64url_decode(parts[2])
    sig_b = b64url_decode(parts[3])
    payload = json.loads(payload_b.decode("utf-8"))
    return kid, payload, payload_b, sig_b


# New signature-only message QR
def make_message_qr_string_sigonly(kid: str, sig: bytes) -> str:
    return f"{MSG_QR_PREFIX_SIGONLY}.{kid}.{b64url_encode(sig)}"


def parse_message_qr_string_sigonly(qr: str) -> Tuple[str, bytes]:
    parts = qr.strip().split(".")
    if len(parts) != 3 or parts[0] != MSG_QR_PREFIX_SIGONLY:
        raise ValueError("Message QR must be: M2.<kid>.<sig_b64url>")
    kid = parts[1]
    sig_b = b64url_decode(parts[2])
    return kid, sig_b


def build_payload_for_text(msg_text: str) -> dict:
    # IMPORTANT: no iat here, so verification doesn't depend on time
    return {"v": 2, "alg": SIG_ALG, "msg": msg_text}


# -----------------------------
# Webcam QR scanner dialog (OpenCV QRCodeDetector)
# -----------------------------
class QRScannerDialog(QDialog):
    """
    Webcam QR scanner using OpenCV QRCodeDetector (no zbar dependency).
    Returns decoded string if found, else None.
    """
    def __init__(self, parent=None, camera_index: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Scan QR Code (Webcam)")
        self.resize(820, 620)

        self._cap = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

        self._detector = cv2.QRCodeDetector()
        self._last_decoded: Optional[str] = None

        v = QVBoxLayout(self)

        self.video_label = QLabel("Starting camera…")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setMinimumHeight(480)
        v.addWidget(self.video_label, 1)

        btns = QHBoxLayout()
        v.addLayout(btns)

        self.btn_start = QPushButton("Start")
        self.btn_start.clicked.connect(lambda: self.start(camera_index))
        btns.addWidget(self.btn_start)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.stop)
        btns.addWidget(self.btn_stop)

        self.status = QLabel("")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.status)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        v.addWidget(self.btn_cancel)

        # Auto-start
        self.start(camera_index)

    def start(self, camera_index: int = 0):
        self.stop()
        self._cap = cv2.VideoCapture(camera_index)
        if not self._cap.isOpened():
            self.status.setText("❌ Could not open camera. Try another camera index.")
            return
        self.status.setText("Scanning… hold QR steady in view.")
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

        # detectAndDecodeMulti gives better results if multiple codes exist
        try:
            retval, decoded_info, points, _ = self._detector.detectAndDecodeMulti(frame)
        except Exception:
            retval = False
            decoded_info = []
            points = None

        # draw box if found
        if points is not None and len(points) > 0:
            for quad in points:
                quad = quad.astype(int)
                cv2.polylines(frame, [quad], isClosed=True, color=(0, 255, 0), thickness=2)

        # show frame
        pix = cv_bgr_to_qpixmap(frame)
        self.video_label.setPixmap(pix.scaled(
            self.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))

        if retval and decoded_info:
            # pick first non-empty
            decoded = next((s for s in decoded_info if s), None)
            if decoded:
                self._last_decoded = decoded.strip()
                self.status.setText("✅ QR detected. Closing…")
                # small delay makes UX nicer
                self._timer.stop()
                QTimer.singleShot(200, self.accept)

    def get_result(self) -> Optional[str]:
        return self._last_decoded

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)


# -----------------------------
# UI
# -----------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA QR Sign/Verify with Key Registry (Qt)")
        self.resize(1200, 860)

        self.registry = KeyRegistry(REGISTRY_PATH)
        self._qr_pil: Optional[Image.Image] = None

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        self.tab_keys = QWidget()
        self.tab_sign = QWidget()
        self.tab_verify = QWidget()

        tabs.addTab(self.tab_keys, "1) Keys (Registry)")
        tabs.addTab(self.tab_sign, "2) Sign → QR")
        tabs.addTab(self.tab_verify, "3) Verify")

        self._build_keys_tab()
        self._build_sign_tab()
        self._build_verify_tab()

        self.refresh_keys_table()
        self.refresh_sign_key_list()

    # ------------- Keys tab -------------
    def _build_keys_tab(self):
        layout = QVBoxLayout(self.tab_keys)

        top = QHBoxLayout()
        layout.addLayout(top)

        # add manually
        add_box = QGroupBox("Add / Update Public Key")
        top.addWidget(add_box, 1)
        form = QFormLayout(add_box)

        self.kid_in = QLineEdit()
        self.name_in = QLineEdit()
        self.pubkey_pem_in = QTextEdit()
        self.pubkey_pem_in.setPlaceholderText("Paste RSA PUBLIC KEY PEM here (-----BEGIN PUBLIC KEY----- ...)")
        self.pubkey_pem_in.setFixedHeight(160)

        form.addRow("Key ID (kid):", self.kid_in)
        form.addRow("Name:", self.name_in)
        form.addRow("Public Key (PEM):", self.pubkey_pem_in)

        row = QHBoxLayout()
        self.btn_add_update = QPushButton("Add/Update Public Key")
        self.btn_add_update.clicked.connect(self.on_add_update_key)
        row.addWidget(self.btn_add_update)

        self.btn_import_pub_pem = QPushButton("Import Public Key PEM File…")
        self.btn_import_pub_pem.clicked.connect(self.on_import_public_pem_file)
        row.addWidget(self.btn_import_pub_pem)

        form.addRow(row)

        # import from key-QR
        qr_box = QGroupBox("Import Key via QR")
        top.addWidget(qr_box, 1)
        v = QVBoxLayout(qr_box)

        self.key_qr_in = QTextEdit()
        self.key_qr_in.setPlaceholderText("Paste Key QR string OR scan with webcam.\nFormat: K1.<kid>.<name_b64url>.<pubkey_der_b64url>")
        v.addWidget(self.key_qr_in)

        qr_btns = QHBoxLayout()
        v.addLayout(qr_btns)

        self.btn_scan_key_qr = QPushButton("Scan Key QR (Webcam)")
        self.btn_scan_key_qr.clicked.connect(self.on_scan_key_qr_webcam)
        qr_btns.addWidget(self.btn_scan_key_qr)

        self.btn_import_key_qr = QPushButton("Import Key QR Text")
        self.btn_import_key_qr.clicked.connect(self.on_import_key_qr)
        qr_btns.addWidget(self.btn_import_key_qr)

        # table
        table_box = QGroupBox("Registered Keys")
        layout.addWidget(table_box, 1)
        tv = QVBoxLayout(table_box)

        self.keys_table = QTableWidget(0, 4)
        self.keys_table.setHorizontalHeaderLabels(["kid", "name", "has private?", "pubkey (DER b64url, first 24 chars)"])
        self.keys_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.keys_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.keys_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.keys_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        tv.addWidget(self.keys_table)

        btns = QHBoxLayout()
        tv.addLayout(btns)

        self.btn_delete_key = QPushButton("Delete Selected Key")
        self.btn_delete_key.clicked.connect(self.on_delete_selected_key)
        btns.addWidget(self.btn_delete_key)

        self.btn_make_key_qr = QPushButton("Make Key QR for Selected Key")
        self.btn_make_key_qr.clicked.connect(self.on_make_key_qr_for_selected)
        btns.addWidget(self.btn_make_key_qr)

        self.key_qr_out = QTextEdit()
        self.key_qr_out.setReadOnly(True)
        self.key_qr_out.setFixedHeight(90)
        tv.addWidget(QLabel("Key QR Output:"))
        tv.addWidget(self.key_qr_out)

        self.key_qr_img_label = QLabel("(Key QR preview here)")
        self.key_qr_img_label.setAlignment(Qt.AlignCenter)
        tv.addWidget(self.key_qr_img_label)

    def refresh_keys_table(self):
        keys = self.registry.list()
        self.keys_table.setRowCount(len(keys))
        for r, entry in enumerate(keys):
            self.keys_table.setItem(r, 0, QTableWidgetItem(entry.kid))
            self.keys_table.setItem(r, 1, QTableWidgetItem(entry.name))
            self.keys_table.setItem(r, 2, QTableWidgetItem("yes" if entry.privkey_path else "no"))
            preview = entry.pubkey_der_b64url[:24] + "..."
            self.keys_table.setItem(r, 3, QTableWidgetItem(preview))

    def selected_kid(self) -> Optional[str]:
        sel = self.keys_table.selectedItems()
        if not sel:
            return None
        row = sel[0].row()
        item = self.keys_table.item(row, 0)
        return item.text() if item else None

    def on_add_update_key(self):
        try:
            kid = self.kid_in.text().strip()
            name = self.name_in.text().strip()
            pem = self.pubkey_pem_in.toPlainText().strip()
            if not kid:
                raise ValueError("kid is required.")
            if not pem:
                raise ValueError("Public key PEM is required.")

            pub = serialization.load_pem_public_key(pem.encode("utf-8"))
            der = rsa_public_key_to_der(pub)
            # keep any existing private key path if present
            existing = self.registry.get(kid)
            priv_path = existing.privkey_path if existing else None

            entry = KeyEntry(kid=kid, name=name, pubkey_der_b64url=b64url_encode(der), privkey_path=priv_path)
            self.registry.upsert(entry)

            self.refresh_keys_table()
            self.refresh_sign_key_list()
            QMessageBox.information(self, "OK", f"Saved public key under kid={kid}.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_import_public_pem_file(self):
        try:
            path, _ = QFileDialog.getOpenFileName(self, "Select public key PEM", "", "PEM (*.pem *.pub);;All files (*)")
            if not path:
                return
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
            self.pubkey_pem_in.setPlainText(pem)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_scan_key_qr_webcam(self):
        dlg = QRScannerDialog(self)
        if dlg.exec() == QDialog.Accepted:
            qr = dlg.get_result()
            if qr:
                self.key_qr_in.setPlainText(qr)
                # auto-import for convenience
                try:
                    kid, name, pub_der = parse_key_qr_string(qr)
                    entry = KeyEntry(kid=kid, name=name, pubkey_der_b64url=b64url_encode(pub_der), privkey_path=None)
                    # preserve private key if kid already exists
                    existing = self.registry.get(kid)
                    if existing and existing.privkey_path:
                        entry.privkey_path = existing.privkey_path
                    self.registry.upsert(entry)
                    self.refresh_keys_table()
                    self.refresh_sign_key_list()
                    QMessageBox.information(self, "Imported", f"Imported key from webcam:\n kid={kid}\n name={name}")
                except Exception as e:
                    QMessageBox.warning(self, "Scanned", f"Scanned text, but import failed:\n{e}")

    def on_import_key_qr(self):
        try:
            qr = self.key_qr_in.toPlainText().strip()
            kid, name, pub_der = parse_key_qr_string(qr)
            entry = KeyEntry(kid=kid, name=name, pubkey_der_b64url=b64url_encode(pub_der), privkey_path=None)
            existing = self.registry.get(kid)
            if existing and existing.privkey_path:
                entry.privkey_path = existing.privkey_path
            self.registry.upsert(entry)

            self.refresh_keys_table()
            self.refresh_sign_key_list()
            QMessageBox.information(self, "OK", f"Imported key QR: kid={kid}, name={name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_delete_selected_key(self):
        try:
            kid = self.selected_kid()
            if not kid:
                QMessageBox.warning(self, "Delete", "Select a key first.")
                return
            self.registry.delete(kid)
            self.refresh_keys_table()
            self.refresh_sign_key_list()
            self.key_qr_out.clear()
            self.key_qr_img_label.setText("(Key QR preview here)")
            QMessageBox.information(self, "Deleted", f"Deleted kid={kid}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_make_key_qr_for_selected(self):
        try:
            kid = self.selected_kid()
            if not kid:
                QMessageBox.warning(self, "Key QR", "Select a key first.")
                return
            entry = self.registry.get(kid)
            if not entry:
                raise ValueError("Key not found.")

            pub_der = b64url_decode(entry.pubkey_der_b64url)
            qr_str = make_key_qr_string(entry.kid, entry.name, pub_der)
            self.key_qr_out.setPlainText(qr_str)

            img = qrcode.make(qr_str).resize((340, 340))
            self.key_qr_img_label.setPixmap(pil_to_qpixmap(img))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ------------- Sign tab -------------
    def _build_sign_tab(self):
        layout = QHBoxLayout(self.tab_sign)

        left = QVBoxLayout()
        right = QVBoxLayout()
        layout.addLayout(left, 2)
        layout.addLayout(right, 1)

        # Add/Import private key
        priv_box = QGroupBox("Private Key (for signing)")
        left.addWidget(priv_box)
        form = QFormLayout(priv_box)

        self.sign_kid_in = QLineEdit()
        self.sign_kid_in.setPlaceholderText("kid to associate with this private key and to sign with (e.g., alice)")
        form.addRow("kid:", self.sign_kid_in)

        self.sign_name_in = QLineEdit()
        self.sign_name_in.setPlaceholderText("Optional display name (e.g., Alice)")
        form.addRow("name:", self.sign_name_in)

        self.privkey_pem_in = QTextEdit()
        self.privkey_pem_in.setPlaceholderText("Paste RSA PRIVATE KEY PEM (PKCS8) here (-----BEGIN PRIVATE KEY----- ...)")
        self.privkey_pem_in.setFixedHeight(170)
        form.addRow("Private key (PEM):", self.privkey_pem_in)

        priv_btns = QHBoxLayout()
        self.btn_import_priv_pem = QPushButton("Import Private Key PEM File…")
        self.btn_import_priv_pem.clicked.connect(self.on_import_private_pem_file)
        priv_btns.addWidget(self.btn_import_priv_pem)

        self.btn_add_private_key = QPushButton("Add/Update Private Key in Registry")
        self.btn_add_private_key.clicked.connect(self.on_add_private_key_to_registry)
        priv_btns.addWidget(self.btn_add_private_key)

        form.addRow(priv_btns)

        self.btn_generate_demo_keypair = QPushButton("Generate Demo RSA Keypair (creates + stores private key)")
        self.btn_generate_demo_keypair.clicked.connect(self.on_generate_demo_keypair)
        form.addRow(self.btn_generate_demo_keypair)

        self.sign_keys_hint = QLabel("")
        self.sign_keys_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Signable kids:", self.sign_keys_hint)

        # message input
        msg_box = QGroupBox("Message Text")
        left.addWidget(msg_box)
        v = QVBoxLayout(msg_box)
        self.sign_msg_in = QTextEdit()
        self.sign_msg_in.setPlaceholderText("Enter the message text. (This text will NOT be embedded in the QR; only the signature will.)")
        v.addWidget(self.sign_msg_in)

        # sign button
        self.btn_sign_make_qr = QPushButton("Sign Text → Generate Message QR (Signature-only)")
        self.btn_sign_make_qr.clicked.connect(self.on_sign_make_message_qr_sigonly)
        left.addWidget(self.btn_sign_make_qr)

        # outputs
        out_box = QGroupBox("Outputs")
        left.addWidget(out_box, 1)
        ov = QVBoxLayout(out_box)

        ov.addWidget(QLabel("Payload JSON used for signing (canonicalized):"))
        self.payload_out = QTextEdit()
        self.payload_out.setReadOnly(True)
        self.payload_out.setFixedHeight(140)
        ov.addWidget(self.payload_out)

        ov.addWidget(QLabel("Signature (base64url):"))
        self.sig_out = QTextEdit()
        self.sig_out.setReadOnly(True)
        self.sig_out.setFixedHeight(70)
        ov.addWidget(self.sig_out)

        ov.addWidget(QLabel("Message QR (signature-only):  M2.kid.sig"))
        self.msg_qr_out = QTextEdit()
        self.msg_qr_out.setReadOnly(True)
        self.msg_qr_out.setFixedHeight(110)
        ov.addWidget(self.msg_qr_out)

        # QR preview
        qr_box = QGroupBox("QR Preview")
        right.addWidget(qr_box, 1)
        qv = QVBoxLayout(qr_box)
        self.msg_qr_img_label = QLabel("(Message QR preview)")
        self.msg_qr_img_label.setAlignment(Qt.AlignCenter)
        qv.addWidget(self.msg_qr_img_label, 1)

        self.btn_copy_msg_qr = QPushButton("Copy Message QR String")
        self.btn_copy_msg_qr.clicked.connect(self.on_copy_message_qr)
        right.addWidget(self.btn_copy_msg_qr)

        self.btn_save_msg_qr_png = QPushButton("Save Message QR PNG…")
        self.btn_save_msg_qr_png.clicked.connect(self.on_save_message_qr_png)
        right.addWidget(self.btn_save_msg_qr_png)

    def refresh_sign_key_list(self):
        signable = []
        for e in self.registry.list():
            if e.privkey_path and os.path.exists(e.privkey_path):
                signable.append(f"{e.kid} ({e.name})")
        self.sign_keys_hint.setText(", ".join(signable) if signable else "(none)")

    def on_import_private_pem_file(self):
        try:
            path, _ = QFileDialog.getOpenFileName(self, "Select private key PEM", "", "PEM (*.pem *.key);;All files (*)")
            if not path:
                return
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
            self.privkey_pem_in.setPlainText(pem)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_add_private_key_to_registry(self):
        try:
            kid = self.sign_kid_in.text().strip()
            if not kid:
                raise ValueError("kid is required.")
            name = self.sign_name_in.text().strip() or kid

            pem_text = self.privkey_pem_in.toPlainText().strip()
            if not pem_text:
                raise ValueError("Paste/import a private key PEM first.")

            priv = load_private_key_pem_from_text(pem_text)
            pub = priv.public_key()
            pub_der = rsa_public_key_to_der(pub)

            # store private key in keystore
            priv_path = os.path.join(KEYSTORE_DIR, f"{kid}_private.pem")
            save_private_key_pem(priv, priv_path)

            entry = KeyEntry(
                kid=kid,
                name=name,
                pubkey_der_b64url=b64url_encode(pub_der),
                privkey_path=priv_path
            )
            self.registry.upsert(entry)
            self.refresh_keys_table()
            self.refresh_sign_key_list()

            QMessageBox.information(self, "OK", f"Saved private key for kid={kid}\nPrivate key stored at:\n{priv_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_generate_demo_keypair(self):
        try:
            kid = self.sign_kid_in.text().strip()
            if not kid:
                raise ValueError("Enter a kid first (e.g., demo1).")
            name = self.sign_name_in.text().strip() or f"Demo key {kid}"

            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            pub_der = rsa_public_key_to_der(pub)

            priv_path = os.path.join(KEYSTORE_DIR, f"{kid}_private.pem")
            save_private_key_pem(priv, priv_path)

            entry = KeyEntry(
                kid=kid,
                name=name,
                pubkey_der_b64url=b64url_encode(pub_der),
                privkey_path=priv_path
            )
            self.registry.upsert(entry)
            self.refresh_keys_table()
            self.refresh_sign_key_list()

            QMessageBox.information(self, "OK", f"Generated demo keypair for kid={kid}\nPrivate key saved:\n{priv_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_sign_make_message_qr_sigonly(self):
        try:
            kid = self.sign_kid_in.text().strip()
            if not kid:
                raise ValueError("Enter kid to sign with (must have private key).")
            entry = self.registry.get(kid)
            if not entry:
                raise ValueError(f"kid={kid} not found in registry.")
            if not entry.privkey_path or not os.path.exists(entry.privkey_path):
                raise ValueError("This kid has no stored private key. Add/import private key first.")

            msg = self.sign_msg_in.toPlainText()
            if not msg.strip():
                raise ValueError("Message is empty.")

            payload = build_payload_for_text(msg)
            payload_b = canonical_json_bytes(payload)

            priv = load_private_key_pem(entry.privkey_path)
            sig = sign_with_private_key(priv, payload_b)

            qr_str = make_message_qr_string_sigonly(kid, sig)

            self.payload_out.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
            self.sig_out.setPlainText(b64url_encode(sig))
            self.msg_qr_out.setPlainText(qr_str)

            img = qrcode.make(qr_str).resize((380, 380))
            self._qr_pil = img
            self.msg_qr_img_label.setPixmap(pil_to_qpixmap(img))

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_copy_message_qr(self):
        qr_str = self.msg_qr_out.toPlainText().strip()
        if not qr_str:
            QMessageBox.warning(self, "Copy", "No message QR string to copy.")
            return
        QApplication.clipboard().setText(qr_str)
        QMessageBox.information(self, "Copy", "Copied message QR string.")

    def on_save_message_qr_png(self):
        if self._qr_pil is None:
            QMessageBox.warning(self, "Save", "Generate a message QR first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Message QR as PNG", "message_qr.png", "PNG (*.png)")
        if not path:
            return
        self._qr_pil.save(path, format="PNG")
        QMessageBox.information(self, "Saved", f"Saved to:\n{path}")

    # ------------- Verify tab -------------
    def _build_verify_tab(self):
        layout = QVBoxLayout(self.tab_verify)

        box = QGroupBox("Verify (Scan QR + Enter Text)")
        layout.addWidget(box, 1)
        v = QVBoxLayout(box)

        # QR input + scan
        qr_row = QHBoxLayout()
        v.addLayout(qr_row)

        self.verify_qr_in = QTextEdit()
        self.verify_qr_in.setPlaceholderText(
            "Paste Message QR string OR scan with webcam.\n"
            "New format: M2.<kid>.<sig_b64url>\n"
            "Legacy:     M1.<kid>.<payload_b64url>.<sig_b64url>"
        )
        self.verify_qr_in.setFixedHeight(120)
        qr_row.addWidget(self.verify_qr_in, 3)

        scan_col = QVBoxLayout()
        qr_row.addLayout(scan_col, 1)

        self.btn_scan_msg_qr = QPushButton("Scan Message QR (Webcam)")
        self.btn_scan_msg_qr.clicked.connect(self.on_scan_message_qr_webcam)
        scan_col.addWidget(self.btn_scan_msg_qr)

        self.btn_verify_msg_qr = QPushButton("Verify")
        self.btn_verify_msg_qr.clicked.connect(self.on_verify_message_qr)
        scan_col.addWidget(self.btn_verify_msg_qr)

        self.verify_result = QLabel("")
        self.verify_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.verify_result)

        # text input for verification
        v.addWidget(QLabel("Text to verify against (REQUIRED for M2 signature-only QR):"))
        self.verify_text_in = QTextEdit()
        self.verify_text_in.setPlaceholderText("Paste/type the exact message text that was signed.")
        self.verify_text_in.setFixedHeight(140)
        v.addWidget(self.verify_text_in)

        # decoded payload
        v.addWidget(QLabel("Decoded payload JSON:"))
        self.decoded_payload = QTextEdit()
        self.decoded_payload.setReadOnly(True)
        self.decoded_payload.setFixedHeight(220)
        v.addWidget(self.decoded_payload)

    def on_scan_message_qr_webcam(self):
        dlg = QRScannerDialog(self)
        if dlg.exec() == QDialog.Accepted:
            qr = dlg.get_result()
            if qr:
                self.verify_qr_in.setPlainText(qr)

    def on_verify_message_qr(self):
        try:
            qr = self.verify_qr_in.toPlainText().strip()
            if not qr:
                raise ValueError("Empty QR string.")

            if qr.startswith(MSG_QR_PREFIX_SIGONLY + "."):
                # New workflow: M2.kid.sig
                kid, sig_bytes = parse_message_qr_string_sigonly(qr)

                entry = self.registry.get(kid)
                if not entry:
                    raise ValueError(f"Unknown kid={kid}. Add this public key to registry first.")

                msg = self.verify_text_in.toPlainText()
                if not msg.strip():
                    raise ValueError("For M2 signature-only QR, you must enter the message text to verify.")

                payload = build_payload_for_text(msg)
                payload_bytes = canonical_json_bytes(payload)

                pub = entry.public_key()
                verify_with_public_key(pub, payload_bytes, sig_bytes)

                self.decoded_payload.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
                self.verify_result.setText(f"✅ VALID (M2) signature for kid={kid} ({entry.name})")
                return

            elif qr.startswith(MSG_QR_PREFIX_LEGACY + "."):
                # Legacy workflow: message embedded in QR
                kid, payload_obj, payload_bytes, sig_bytes = parse_message_qr_string_legacy(qr)

                entry = self.registry.get(kid)
                if not entry:
                    raise ValueError(f"Unknown kid={kid}. Add this public key to registry first.")

                pub = entry.public_key()
                verify_with_public_key(pub, payload_bytes, sig_bytes)

                self.decoded_payload.setPlainText(json.dumps(payload_obj, ensure_ascii=False, indent=2, sort_keys=True))

                # If user typed text, compare with payload msg (optional)
                typed = self.verify_text_in.toPlainText().strip()
                embedded = str(payload_obj.get("msg", "")).strip()
                if typed and embedded and typed != embedded:
                    self.verify_result.setText(f"✅ VALID (M1) signature for kid={kid} ({entry.name}) — ⚠️ typed text does not match embedded msg")
                else:
                    self.verify_result.setText(f"✅ VALID (M1) signature for kid={kid} ({entry.name})")
                return

            else:
                raise ValueError("Unknown QR format. Expected M2.* or M1.*")

        except InvalidSignature:
            self.verify_result.setText("❌ INVALID signature")
            self.decoded_payload.clear()
        except Exception as e:
            self.verify_result.setText(f"❌ {e}")
            self.decoded_payload.clear()


def main():
    app = QApplication([])
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()