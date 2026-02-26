# QR_Code_verifier
The goal of this code is to be able to verify a message using the QR code that is attached to it. This app allows the sender of any message (text only) to generate a digital signature and send it along the text. 

The receiver of the message and the QR code, must know the public key of the sender, usese this app and verify that the message was indeed sent by the true sender and is not modified.

To make sure that the application code itself is not modifed below is the hash of the python code itself is

- qr_verify_app.py hash
```hash
9bad87fae64a3e564bc4d7374a2bafc13023c0377968bcf6c805c0748e588750
```

- qr_signer_app.py hash
``` hash
db315c77001c10ef3cf6500a3edd122901e4cf366049e59fda57f2e0fb568aaf
```

- Scan the signed_public_key.png QR code and check if it verifies and matches with the stored public key in the [public_keys.json](public_keys.json) file. It must match.

<p align="center">
  <img src="signed_public_key.png" alt="Signed public key" width="220" />
</p>


# How to use

###  1- Install UV 
- Linux/MAC
```bash 
curl -LsSf https://astral.sh/uv/install.sh | sh
```
- Windows
```bash
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```


### 2- install Git (optional)
you don't have to install git and can download the repository directly.

you can clone the repo using below:
```bash
git clone https://github.com/mkashani-phd/QR_code_verifier.git
cd QR_code_verifier
```


## 3- Run the verifier
Using powershell or the terminal and navigate to the QR_code_verifier folder and run the following code. 
``` bash
uv run qr_verify_app.py
```


# How to generate a key pair

- SSH key
``` bash
ssh-keygen -t ed25519 -C "comment"
```

- RSA
``` bash
 openssl genrsa -out xxx_private.pem 2048
 openssl rsa -in xxx_private_key.pem -pubout -out xxx_key.pem
```
**note:** 
- Moh can be replaced with anything and is indicative of the senders info

- Make sure that you don't make the private key public!!!

- It is the receiver's responsibility to make sure that they have the corret public key of the reciever! I suppose creating a block chain of the trusted public key won't be a bad idea.

