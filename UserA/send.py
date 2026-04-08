from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import myRSA

message = "Hello B. What time we play tennis today?".encode("utf-8")

# ====== PGP Authentication ======
# Step 1 : Load Keys
PU_B = RSA.import_key(open("../PKI/PU_B.pem").read())
PR_A = RSA.import_key(open("../UserA/PR_A.pem").read())

# Step 2. Create Digital Signature 
hash_message = SHA1.new(message)

# Step 3 : Sign the hash using Sender's Private Key (PR_A)
signature = myRSA.encryptBytes(hash_message.digest(), PR_A)

# ====== PGP Confidentiality ======
# Step 1 : Generate random 128-bit number as session key
session_key = get_random_bytes(16)

# Step 2 : use AES (symmetric encryption) 
# to encrypt the message with the SESSION KEY
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, digest = cipher_aes.encrypt_and_digest(message)

# Step 3 : RSA-encrypt the session key with RECEIVER'S PUBLIC KEY
enc_session_key = myRSA.encryptBytes(session_key, PU_B)

# Step 4 : Write to mailserver
# {m}SSSK || {hash}PR_S || {SSSK}PU_R
with open("../mailserver/email1", "wb") as f:
    # Encrypted Session Key
    f.write(len(enc_session_key).to_bytes(2, "big"))
    f.write(enc_session_key) 
    
    # AES Metadata (Fixed 16-byte lengths)
    f.write(cipher_aes.nonce) 
    f.write(digest) 
    
    # Digital Signature (Variable length)
    f.write(len(signature).to_bytes(2, "big"))
    f.write(signature)
    
    # Ciphertext 
    f.write(ciphertext)
