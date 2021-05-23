from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

#=======================================================================================

def generateAESkey():
    # key AES 256 bits
    key = get_random_bytes(32)

    # save AES key
    with open('AESkey', 'wb') as f:
        f.write(key)
        f.close()

def encrypt_textfile(file, key):
    # open file txt
    with open(file, 'r') as f:
        fp = f.read()

    # open file AES key
    with open(key, 'rb') as f:
        k = f.read()

    # get AES key to encrypt text
    cipher = AES.new(k, AES.MODE_EAX)
    iv = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(fp.encode('UTF-8'))

    print("iv : ", iv)
    print("ciphertext : ",ciphertext)

    # len iv = 16 | tag = 16
    ciphertext = iv + tag + ciphertext
    print("ciphertext_encrypt : ",ciphertext)

    # save file text encrypt
    with open('AES_encrypt.txt', 'wb') as f:
        f.write(ciphertext)

def decrypt_textfile(file, key):
    #open file encrypt txt
    with open(file, 'rb') as f:
        iv  = f.read(16)
        tag = f.read(16)
        textdata = f.read()

    # open file AES key
    with open(key, 'rb') as f:
        k = f.read()

    cipher = AES.new(k, AES.MODE_EAX, nonce=iv)
    plaintext = cipher.decrypt_and_verify(textdata, tag).decode('UTF-8')

    # save file txt decrypt
    with open('AES_decrypt.txt', 'w') as f:
        f.write(plaintext)
 
def encrypt_picture(file, key):
    # open file picture
    with open(file, 'rb') as f:
        pic = f.read()

    # pad size >> 16 bytes
    pic = pad(pic, AES.block_size)

    # open file AES key
    with open(key, 'rb') as f:
        k = f.read()

    cipher = AES.new(k, AES.MODE_CBC)
    data = cipher.encrypt(pic)

    # save picture encrypt
    with open('Picture_encrypt', 'wb') as f:
        f.write(cipher.iv)
        f.write(data)

def decrypt_picture(file, key):
    # open picture decrypt
    with open(file, 'rb') as f:
        iv = f.read(16)
        data = f.read()

    # open file AES key
    with open(key, 'rb') as f:
        k = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)
    plaintext = unpad(plaintext, AES.block_size)

    # save picture decrypt
    with open('Picture_decrypt.png', 'wb') as f:
        f.write(plaintext)

def generateRSAkey():
    # generate key 2048 bits
    key = RSA.generate(2048)

    Private_Key = key.exportKey('PEM')
    Public_Key = key.publickey().exportKey('PEM')

    with open('Private_Key.pem', 'wb') as f:
        f.write(Private_Key)
        f.close()

    with open('Public_Key.pem', 'wb') as f:
        f.write(Public_Key)
        f.close()

def encrypt_signature(pvt_key, file):
    #get private Key from file
    private_key = RSA.import_key(open(pvt_key).read())

    with open(file, 'rb') as f:
        msg = f.read()
    # hash 512
    digest = SHA512.new()
    digest.update(msg)

    with open('hash', 'wb') as f:
        f.write(digest.digest())

    # sign with private key
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest) 

    print("ciphertext : " ,sig)

    with open('digital_signature', 'wb') as f:
        f.write(sig)
        f.close

def encrypt_signature(pub_key, file, ds, AES):
    #get public Key from file
    public_key = RSA.importKey(open(pub_key).read())

    # get Digital_signature
    with open(ds, 'rb') as f:
        sig = f.read()

    # get file text
    with open(file, 'rb') as f:
        msg = f.read()
    
    # hash 512
    digest = SHA512.new()
    digest.update(msg)

    verifier  = PKCS1_v1_5.new(public_key)
    verify = verifier.verify(digest, sig)

    print("Verify : ",verify)

    if (verify):
        decrypt_textfile(file, AES)

#=======================================================================================

# generatekey AES 256 bits
generateAESkey()

# generatekey Private & Public By RSA 2048 bits
generateRSAkey()

