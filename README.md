# QR_Code_verifier
The goal of this code is to be able to verify a message using the QR code that is attached to it. This app allows the sender of any message (text only) to generate a digital signature and send it along the text. 

The receiver of the message and the QR code, must know the public key of the sender, usese this app and verify that the message was indeed sent by the true sender and is not modified.

To make sure that the application code itself is not modifed below is the hash of the python code itself is

- qr_verify_app.py hash
```hash
57af5dc784c8867ab3ca272b607e45b4348a110a7ca5ab75d5302229af4079f1
```

- qr_signer_app.py hash
``` hash
a94a8319c7d42b1c60c3b60eaf4be3ce54af0c10c3bf6ef43141857f1267838d
```

# How to use

### Install UV 
- Linux/MAC
```bash 
curl -LsSf https://astral.sh/uv/install.sh | sh
```
- Windows
```bash
powershell -c "irm https://astral.sh/uv/install.ps1 | more"
```

## Run the verifier
``` bash
git clone https://github.com/mkashani-phd/QR_code_verifier.git
cd QR_code_verifier
uv run qr_verify_app.py
```


# How to generate a key pair
``` bash
 openssl genrsa -out private_key.pem 2048
 openssl rsa -in private_key.pem -pubout -out public_key.pem
```

Make sure that you don't make the private key public!!!

It is the receiver's responsibility to make sure that they have the corret public key of the reciever! I suppose creating a block chain of the trusted public key won't be a bad idea.

