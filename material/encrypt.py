from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# generate key 256 bits >> 32 bytes
key = get_random_bytes(32)

text = "Secrect"

cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(text.encode('ascii'))

print(f'key : {key}')
print(f"nonce : {nonce}")
print(f"ciphertext : {ciphertext}")
print(f"tag : {tag}")