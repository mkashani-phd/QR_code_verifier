# QR_Code_verifier

## Install UV
```bash 
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/mkashani-phd/QR_code_verifier.git

cd QR_code_verifier
uv run qr_verify_app.py
```


## How to generate a key pair
``` bash
 openssl genrsa -out private_key.pem 2048
 openssl rsa -in private_key.pem -pubout -out public_key.pem
```