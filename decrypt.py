from Crypto.Cipher import AES

# generate key 256 bits >> 32 bytes
key = b'E\xabOw\x04\x8a\x8e&\xd7yke\xb4@(\x02\xe3\x0f1IUuh\xe9j\t\x02\xdbA\x85\xc3Q'
nonce = b'\x06M\xcb\xb2om\x0c\x17\x11\xdcG\x00\xdefA\x1b'
ciphertext = b'\x9aig\xd7)\xd4`'
tag = b'\x93wP\xa9\xf1\xe7*@\x1eE\\\x04sd\x0c@'

# decrypt file which encrypt
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
data = cipher.decrypt_and_verify(ciphertext, tag).decode('ascii')

print("data : ",data)