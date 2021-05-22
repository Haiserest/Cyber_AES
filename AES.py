from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# def encrypt(msg):
#     cipher = AES.new(key, AES.MODE_EAX)
#     nouce = cipher.nonce
#     ciphertext, tag = cipher.encrypt_and_digest(msg)
#     return tag, nouce, ciphertext

# def decrypt(nouce, ciphertext, tag):
#     cipher = AES.new(key, AES.MODE_EAX, nonce=nouce)
#     plaintext = cipher.decrypt(ciphertext)
#     try:
#         cipher.verify(tag)
#         return plaintext
#     except:
#         return "error!!!"

# key = input("create key: ")
# text = input ("input Text to encryption : ")
# tag, nouce, ciphertext = encrypt(text)
# plaintext = decrypt(nouce, ciphertext, tag)
# print("Ciphertext : ", ciphertext)
# print("plaintext : ", plaintext)


# generate key 256 bits >> 32 bytes
key = get_random_bytes(32)
# generate initalization vector 64 bits >> 8 bytes
iv = get_random_bytes(8)

text = "Secrect"

cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(text.encode('ascii'))

print(f"key : {key}")
print(f"iv : {iv}")
print(f"nonce : {nonce}")
print(f"ciphertext : {ciphertext}")
print(f"tag : {tag}")

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
data = cipher.decrypt_and_verify(ciphertext, tag).decode("UTF-8")
print("data : ",data)