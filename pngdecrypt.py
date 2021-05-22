from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open('pic_encrypt', 'rb') as f:
    iv = f.read(16)
    data = f.read()

with open('pickey', 'rb') as f:
    key = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)

plaintext = cipher.decrypt(data)
plaintext = unpad(plaintext, AES.block_size)

with open('decrypty.png', 'wb') as f:
    f.write(plaintext)