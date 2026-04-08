from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Cipher import AES
import myRSA

# Step 0 : Open and Read The Email
with open("../mailserver/email1", "rb") as f:
    # Read Encrypted Session Key
    key_len = int.from_bytes(f.read(2), "big")
    enc_session_key = f.read(key_len)
    
    # Read AES Metadata
    nonce = f.read(16)
    digest = f.read(16)
    
    # Read Digital Signature
    sig_len = int.from_bytes(f.read(2), "big")
    signature = f.read(sig_len)
    
    # Read Ciphertext
    ciphertext = f.read()

# {m}SSSK || {hash}PR_S || {SSSK}PU_R

# ====== PGP Authentication ======
# Step 1 : Load Keys
PR_B = RSA.import_key(open("../UserB/PR_B.pem").read())
PU_A = RSA.import_key(open("../PKI/PU_A.pem").read())

# Step 2 : Decrypt the encrypted session key with the private key of receiver
session_key = myRSA.decryptBytes(enc_session_key, PR_B)
                                
# Step 3 : Decrypt ciphertext with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
plain_message = cipher_aes.decrypt_and_verify(ciphertext, digest)

# Step 4 : Decrypt Signature to get original hash using Sender's Public Key (PU_A)
original_hash = myRSA.decryptBytes(signature, PU_A)

# Step 5 : Compute hash of the plain message
fresh_hash = SHA1.new(plain_message).digest()

# Step 5 : Compare Hash 
if fresh_hash == original_hash:
    print("Success! Message is authentic and unmodified.")
    print("="*45)
    print(plain_message.decode("utf-8"))
else:
    print("Verification failed!")
