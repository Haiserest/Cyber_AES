from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# key AES 256 bits
key = get_random_bytes(32)

with open('pic.png', 'rb') as f:
    pic = f.read()

# pad size >> 16 bytes
pic = pad(pic, AES.block_size)

with open('pickey', 'wb') as f:
    f.write(key)

cipher = AES.new(key, AES.MODE_CBC)

data = cipher.encrypt(pic)

with open('pic_encrypt', 'wb') as f:
    f.write(cipher.iv)
    f.write(data)