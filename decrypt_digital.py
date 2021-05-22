from inspect import Signature, signature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# open PrivateKey file and get PrivateKey
with open('PublicKey.pem', 'rb') as k:
    public_key = serialization.load_pem_public_key(
        k.read(),
        backend=None
    )

# pem = public_key.public_bytes(
#     encoding = serialization.Encoding.PEM,
#     format = serialization.PublicFormat.SubjectPublicKeyInfo
# )
print(public_key)

# open file message
with open('ds_msg.txt', 'rb') as f:
    msg = f.read()

print(public_key)

# decrypt public key By private key
# plaintext = public_key.decrypt(
#     msg,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA512()),
#         algorithm=hashes.SHA512(),
#         label=None
#     )
# )

plaintext = public_key.verify(
    signature,
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

print("plaintext : ",plaintext)