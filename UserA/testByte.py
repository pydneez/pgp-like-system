import os
from Crypto.PublicKey import RSA
import myRSA


# ── Load keys ──────────────────────────────────────────────────────────────────
PU_A = RSA.import_key(open("../PKI/PU_A.pem").read())
PU_B = RSA.import_key(open("../PKI/PU_B.pem").read())
PR_A = RSA.import_key(open("../UserA/PR_A.pem").read())
PR_B = RSA.import_key(open("../UserB/PR_B.pem").read())


print("=" * 55)
print("  TEST 1 — Encrypt bytes with A's public key, decrypt with A's private key")
print("=" * 55)

session_key = os.urandom(16)          # simulate a random 16-byte AES key
print(f"Original  (hex) : {session_key.hex()}")
print(f"Original  (raw) : {session_key}")
print(f"Length          : {len(session_key)} bytes\n")


encrypted = myRSA.encryptBytes(session_key, PU_A)
print(f"Encrypted (hex) : {encrypted.hex()}")
print(f"Encrypted length: {len(encrypted)} bytes\n")

decrypted = myRSA.decryptBytes(encrypted, PR_A)
print(f"Decrypted (hex) : {decrypted.hex()}")
print(f"Match           : {session_key == decrypted}")

print()
print("=" * 55)
print("  TEST 2 — PGP style: A encrypts session key with B's public key")
print("           Only B (with PR_B) can decrypt it")
print("=" * 55)

session_key2 = os.urandom(16)
print(f"Session key     : {session_key2.hex()}\n")

# A encrypts using B's public key
enc_for_B = myRSA.encryptBytes(session_key2, PU_B)
print(f"Encrypted for B : {enc_for_B.hex()}\n")

# B decrypts using B's private key
recovered_by_B = myRSA.decryptBytes(enc_for_B, PR_B)
print(f"B recovers key  : {recovered_by_B.hex()}")
print(f"Match           : {session_key2 == recovered_by_B}")

print()
print("=" * 55)
print("  TEST 3 — Wrong key should NOT decrypt correctly")
print("=" * 55)

session_key3 = os.urandom(16)
enc = myRSA.encryptBytes(session_key3, PU_B)

# A tries to decrypt something encrypted for B — should fail
try:
    wrong = myRSA.decryptBytes(enc, PR_A)   # wrong private key
    print(f"Original  : {session_key3.hex()}")
    print(f"Got       : {wrong.hex()}")
    print(f"Match     : {session_key3 == wrong}  ← should be False")
except Exception as ex:
    print(f"Decryption failed as expected: {ex}")

print()
print("=" * 55)
print("  TEST 4 — Right key should decrypt correctly")
print("=" * 55)

    # A tries to decrypt something encrypted for B — should pass
try:
    wrong = myRSA.decryptBytes(enc, PR_B)   # right private key
    print(f"Original  : {session_key3.hex()}")
    print(f"Got       : {wrong.hex()}")
    print(f"Match     : {session_key3 == wrong}  ← should be True")
except Exception as ex:
    print(f"Decryption failed as expected: {ex}")