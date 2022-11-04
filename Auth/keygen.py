from Crypto.PublicKey import RSA

'''This file is used for generating the public and private keys RSA Asymmetric Encryption'''
#Only run one time to generate public.pem and private.pem

key = RSA.generate(1024)
private_key = key.exportKey()
with open("private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().exportKey()
with open("public.pem","wb") as f:
    f.write(public_key)

