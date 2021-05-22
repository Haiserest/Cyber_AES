import hashlib
from inspect import signature
from Crypto.Util.Padding import pad
from cryptography import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding,utils

# open privatekey file and get key
with open('PrivateKey.pem', 'rb') as k:
    private_key = serialization.load_pem_private_key(
        k.read(),
        password=None,
        backend=default_backend()
    )

public_key = private_key.public_key()
print(public_key)
pem = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('PublicKey.pem', 'wb') as k:
    k.write(pem)

msg = b"secrect"
msg = hashlib.sha512(msg).digest()
print("msg : ",msg)

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

cipher = private_key.sign(
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

public_key.verify(
    signature,
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

print("cipher : " ,cipher)
#print("plaintext : ",plaintext)

with open('ds_msg.txt', 'wb') as f:
    f.write(cipher)
    f.close()