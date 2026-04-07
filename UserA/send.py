from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import myRSA

data = "Hello B. What time we play tennis today?".encode("utf-8")

PU_B = RSA.import_key(open("../PKI/PU_B.pem").read())
session_key = get_random_bytes(16)

# Step 1: RSA-encrypt the session key with RECEIVER'S PUBLIC KEY
enc_session_key = myRSA.encryptBytes(session_key, PU_B)

# Step 2: AES-encrypt the message with the SESSION KEY
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, digest = cipher_aes.encrypt_and_digest(data)

# MAC = message authentication code
# MAC of a message m = {h(m)}_K
# different from  a signature

# Write to mailserver
with open("../mailserver/email1", "wb") as f:
    f.write(len(enc_session_key).to_bytes(2, "big"))  # ← add this line
    f.write(enc_session_key)
    f.write(cipher_aes.nonce)
    f.write(digest)
    f.write(ciphertext)
