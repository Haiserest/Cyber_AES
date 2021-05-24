from inspect import signature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512

# open PrivateKey file and get PrivateKey
# with open('PublicKey.pem', 'rb') as k:
#     public_key = serialization.load_pem_public_key(
#         k.read(),
#         backend=None
#     )

public_key = RSA.importKey(open('PublicKey.pem').read())

# pem = public_key.public_bytes(
#     encoding = serialization.Encoding.PEM,
#     format = serialization.PublicFormat.SubjectPublicKeyInfo
# )
print(public_key)

# open file message
# sig
with open('ds_msg.txt', 'rb') as f:
    sig = f.read()
# message
with open('message.txt', 'rb') as f:
    message = f.read()
# msg
with open('msg.txt', 'rb') as f:
    msg = f.read()
    digest = SHA512.new()
    print("digest: " ,digest)
    digest.update(msg)

verifier = PKCS1_v1_5.new(public_key)
verify = verifier.verify(digest, sig)

# decrypt public key By private key
# plaintext = public_key.decrypt(
#     msg,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA512()),
#         algorithm=hashes.SHA512(),
#         label=None
#     )
# )

# plaintext = public_key.verify(
#     signature,
#     msg,
#     padding.PSS(
#         mgf=padding.MGF1(hashes.SHA512()),
#         salt_length=padding.PSS.MAX_LENGTH
#     ),
#     hashes.SHA512()
# )
print("verify: ", verify)
if(verify):
    print("plaintext : ",message)
else:
    print("Not Correct Message!!!!!")