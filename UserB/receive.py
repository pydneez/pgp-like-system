from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import myRSA

# simulate user B receiveing their email
# get their private key
PR_B = RSA.import_key(open("../UserB/PR_B.pem").read())

# open encrypted email from the mail server
with open("../mailserver/email1", "rb") as f:
    key_len = int.from_bytes(f.read(2), "big")        # read length prefix
    enc_session_key = f.read(key_len)
    nonce = f.read(16)
    digest = f.read(16)
    ciphertext = f.read()
        
# Step 1: Decrypt the encrypted session key with the private key of receiver
session_key = myRSA.decryptBytes(enc_session_key, PR_B)

# Step 2: Decrypt ciphertext with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
# pass in the nonce as well

# Step 3: also verify the message authentication code (MAC)
email = cipher_aes.decrypt_and_verify(ciphertext, digest)
print(email.decode("utf-8"))
