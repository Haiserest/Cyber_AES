from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# key AES 256 bits
key = get_random_bytes(32)

# save AES key
with open('AESkey', 'wb') as f:
    f.write(key)

# open file text
with open('text.txt', 'r') as f:
    fp = f.read()


cipher = AES.new(key, AES.MODE_EAX)
iv = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(fp.encode('UTF-8'))

print("iv : ", iv)
print("ciphertext : ",ciphertext)

# len iv = 16 | tag = 16
ciphertext = iv + tag + ciphertext
print("ciphertext_encrypt : ",ciphertext)

with open('encrypt.txt', 'wb') as f:
    f.write(ciphertext)
