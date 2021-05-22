from Crypto.Cipher import AES
import hashlib

#open file text which decrypt
with open('encrypt.txt', 'rb') as f:
    aesfile = f.read()

print(type(aesfile))

msg = hashlib.sha512(aesfile).digest()
print("msg : ",msg)