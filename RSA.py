from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512

def generatekey():
    # generate key 2048 bits
    key = RSA.generate(2048)

    Private_Key = key.exportKey('PEM')
    Public_Key = key.publickey().exportKey('PEM')

    with open('PrivateKey.pem', 'wb') as f:
        f.write(Private_Key)
        f.close()

    with open('PublicKey.pem', 'wb') as f:
        f.write(Public_Key)
        f.close()

generatekey()
msg = "secrect"
