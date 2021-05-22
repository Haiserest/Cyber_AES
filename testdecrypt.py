from Crypto.Cipher import AES

#open AES key
with open('AESKey', 'rb') as f:
    key = f.read() 

#open file text which decrypt
with open('encrypt.txt', 'rb') as f:
    iv_decrypt  = f.read(16)
    tag_decrypt = f.read(16)
    textdata = f.read()

cipher = AES.new(key, AES.MODE_EAX, nonce=iv_decrypt)
plaintext = cipher.decrypt_and_verify(textdata, tag_decrypt).decode('UTF-8')

with open('decrypt.txt', 'w') as f:
    f.write(plaintext)