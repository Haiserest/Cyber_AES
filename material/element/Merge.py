import hashlib
import os

def Write(msg):
    with open('cache', 'a')as f:
        f.write(msg)
        f.write("\n")
        f.close()

def read():
    with open('cache', 'r')as f:
        path = f.readlines()
        path = [pt.strip('\n') for pt in path]
        print(type(path))
        f.seek(0)
        msg = ''.join(path)
        
        print(type(msg))
        msg = hashlib.sha512(msg.encode()).digest()
        with open('cache', 'wb')as f:
            f.write(msg)

def destroy():
    os.remove('cache')

a = "C:/Users/asus/Documents/Cyber/Project/Cyber_AES/material/text.txt"
Write(a)
b = "C:/Users/asus/Documents/Cyber/Project/Cyber_AES/AES/AESkey"
Write(b)
c = "C:/Users/asus/Documents/Cyber/Project/Cyber_AES/RSA/Private_Key.pem"
Write(c)

# read()
destroy()