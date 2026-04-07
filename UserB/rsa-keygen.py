from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
with open("../UserB/PR_B.pem", "wb") as f:
    # write sequence in to the pem file
    # (complex file to store key for rsa)
    f.write(private_key)

public_key = key.publickey().export_key()
with open("../PKI/PU_B.pem", "wb") as f:
    f.write(public_key)
