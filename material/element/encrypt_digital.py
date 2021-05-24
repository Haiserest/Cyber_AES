import hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from base64 import b64encode
from inspect import signature
from Crypto.Util.Padding import pad
from cryptography import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding,utils

# open privatekey file and get key
# with open('PrivateKey.pem', 'rb') as k:
#     private_key = serialization.load_pem_private_key(
#         k.read(),
#         password=None,
#         backend=default_backend()
#     )

# public_key = private_key.public_key()
# print(type(public_key))
# pem = public_key.public_bytes(
#     encoding = serialization.Encoding.PEM,
#     format = serialization.PublicFormat.SubjectPublicKeyInfo
# )

# with open('PublicKey.pem', 'wb') as k:
#     k.write(pem)

private_key = RSA.import_key(open('PrivateKey.pem').read())

print(type(private_key))
msg = b"secrect"
digest = SHA512.new()
print("digest: " ,digest)
digest.update(msg)
print("digest update : " ,digest)
# msg = hashlib.sha512(msg).digest()
# print("msg : ",digest.digest())

with open('msg.txt', 'wb') as f:
    f.write(msg)

with open('message.txt', 'wb') as f:
    f.write(digest.digest())

signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)

# encrypt text with privateKey
# cipher = private_key.encrypt(
#     msg,
#     padding.OAEP(
#         mgf=padding.MGF1(
#             algorithm=hashes.SHA512()),
#             algorithm=hashes.SHA512(),
#             label=None
#     )
# )

# cipher = private_key.sign(
#     msg,
#     padding.PSS(
#         mgf=padding.MGF1(hashes.SHA512()),
#         salt_length=padding.PSS.MAX_LENGTH
#     ),
#     hashes.SHA512()
# )

# public_key.verify(
#     signature,
#     msg,
#     padding.PSS(
#         mgf=padding.MGF1(hashes.SHA512()),
#         salt_length=padding.PSS.MAX_LENGTH
#     ),
#     hashes.SHA512()
# )

print("ciphertext : " ,sig)
#print("plaintext : ",plaintext)

with open('ds_msg.txt', 'wb') as f:
    f.write(sig)
    f.close()