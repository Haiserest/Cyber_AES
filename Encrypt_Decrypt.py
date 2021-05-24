import tkinter
from tkinter import Toplevel, filedialog
from tkinter import *
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

# ===================      Function        ========================================

def generateAESkey():
    # key AES 256 bits
    key = get_random_bytes(32)

    # save AES key
    fileAES = "File_Generate/AES/AESkey"
    os.makedirs(os.path.dirname(fileAES), exist_ok=True)
    with open(fileAES, 'wb') as f:
        f.write(key)
        f.close()

def generateRSAkey():
    # generate key 2048 bits
    key = RSA.generate(2048)

    Private_Key = key.exportKey('PEM')
    Public_Key = key.publickey().exportKey('PEM')

    Private_key_file = "File_Generate/RSA/Private_Key.pem"
    os.makedirs(os.path.dirname(Private_key_file), exist_ok=True)
    with open(Private_key_file, 'wb') as f:
        f.write(Private_Key)
        f.close()

    Public_key_file = "File_Generate/RSA/Public_Key.pem"
    os.makedirs(os.path.dirname(Public_key_file), exist_ok=True)
    with open(Public_key_file, 'wb') as f:
        f.write(Public_Key)
        f.close()

def encrypt_textfile(file, key, pvt_key):

    # AES_encrypt part
    print("\nencrypt_textfile_function")

    # open file txt
    with open(file, 'r') as f:
        fp = f.read()
        print("text: ",fp)

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
    filegenerate = "File_Generate/Encrypt/Text/AES_encrypt.txt"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'wb') as f:
        f.write(ciphertext)

    # Digital_Signal Part
    print("\nencrypt_signature_function")

    #get private Key from file
    private_key = RSA.import_key(open(pvt_key).read())

    # hash 512
    digest = SHA512.new()
    digest.update(ciphertext)

    filegenerate = "File_Generate/Encrypt/Text/hash"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'wb') as f:
        f.write(digest.digest())

    # sign with private key
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest) 

    print("Signature : " ,sig)

    filegenerate = "File_Generate/Encrypt/Text/digital_signature"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'wb') as f:
        f.write(sig)
        f.close

def decrypt_textfile(file, key):
    print("\ndecrypt_textfile_function")
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

    print("plaintext: ",plaintext)

    # save file txt decrypt
    filegenerate = "File_Generate/Decrypt/Text/AES_decrypt.txt"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'w') as f:
        f.write(plaintext)

def decrypt_signature(pub_key, file, ds, AES_key):

    print("\ndecrypt_signature_function")
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
        decrypt_textfile(file, AES_key)
 
def encrypt_picture(file, key):
    print("\nencrypt_Picture_function")
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

    print("Picture_encrypt: ",data)

    # save picture encrypt
    filegenerate = "File_Generate/Encrypt/Picture/Picture_encrypt"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'wb') as f:
        f.write(cipher.iv)
        f.write(data)

def decrypt_picture(file, key):
    print("\ndecrypt_picture_function")

    # open picture decrypt
    with open(file, 'rb') as f:
        iv = f.read(16)
        data = f.read()

    # open file AES key
    with open(key, 'rb') as f:
        k = f.read()

    cipher = AES.new(k, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)

    print("plaintext: ",plaintext)

    plaintext = unpad(plaintext, AES.block_size)

    # save picture decrypt
    filegenerate = "File_Generate/Decrypt/Picture/Picture_decrypt.png"
    os.makedirs(os.path.dirname(filegenerate), exist_ok=True)
    with open(filegenerate, 'wb') as f:
        f.write(plaintext)

# =====================      UI           ============================================

def set_path(entry_field,num):
    path = filedialog.askopenfilename(initialdir = "C:")
    entry_field.delete(0, tkinter.END)
    entry_field.insert(0, path)
    print(path)
    if (num == 11):
        filedircache = "material/cache/cache_txt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w') as f:
            f.write(path)
    elif (num == 12):
        filedircache = "material/cache/cache_A_encrypt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 13):
        filedircache = "material/cache/cache_Pvt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 21):
        filedircache = "material/cache/cache_T_encrypt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 23):
        filedircache = "material/cache/cache_Pub"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 24):
        filedircache = "material/cache/cache_DS"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 22):
        filedircache = "material/cache/cache_A_key"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 31):
        filedircache = "material/cache/cache_P_encrypt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 32):
        filedircache = "material/cache/cache_APE"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 41):
        filedircache = "material/cache/cache_P_decrypt"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    elif (num == 42):
        filedircache = "material/cache/cache_APD"
        os.makedirs(os.path.dirname(filedircache), exist_ok=True)
        with open(filedircache, 'w')as f:
            f.write(path)
    
def tutorialText():
    Text_tutorial = Toplevel(Application)
    Text_tutorial.minsize(width=500, height=300)
    my_text = tkinter.Label(Text_tutorial)
    my_text.pack(side=tkinter.LEFT, fill=BOTH, expand=True)

    tt_file = "material/temp/Tutorial_Encrypt_Decrypt_text.txt"
    tfile = open(tt_file, 'r')
    stuff = tfile.read()
    print(stuff)
    my_text.configure(text=stuff)
    

def text_encrypt_func():
    filedircache = "material/cache/cache_txt"
    with open(filedircache, 'r') as f:
        filetext = f.read()

    filedircache = "material/cache/cache_A_encrypt"
    with open(filedircache, 'r') as f:
        AES_keyencrypt = f.read()
    
    filedircache = "material/cache/cache_Pvt"
    with open(filedircache, 'r')as f:
        pvt_key = f.read()

    print("filetext: ",filetext)
    print("AES_keyencrypt: ",AES_keyencrypt)
    print("pvt_key: ",pvt_key)
    encrypt_textfile(filetext, AES_keyencrypt, pvt_key)

def text_decrypt_func():

    filedircache = "material/cache/cache_T_encrypt"
    with open(filedircache, 'r')as f:
        filetext = f.read()
    
    filedircache = "material/cache/cache_Pub"
    with open(filedircache, 'r')as f:
        pub = f.read()
    
    filedircache = "material/cache/cache_DS"
    with open(filedircache, 'r')as f:
        ds = f.read()

    filedircache = "material/cache/cache_A_key"
    with open(filedircache, 'r')as f:
        AES_keyencrypt = f.read()

    print("AES_encrypt: ",filetext)
    print("AES_keyencrypt: ",AES_keyencrypt)
    print("pub_key: ",pub)
    print("DS: ",ds)

    decrypt_signature(pub, filetext, ds, AES_keyencrypt)

def encryptText():
    Text_encrypt = Toplevel(Application)
    Text_encrypt.minsize(width=500, height=300)
    Text_encrypt.title("Encrypt Text")
    Text_encrypt.columnconfigure([0,2,4,6], minsize=20)
    Text_encrypt.rowconfigure([0,2,4,6], minsize=20)

    # browse field
    path_txt_label = tkinter.Label(Text_encrypt, text="Text.txt", font="Raleway")
    path_txt_label.grid(column=1, row=1)

    txt_path = tkinter.Entry(Text_encrypt, width=50)
    txt_path.grid(column=3, row=1)

    btn_txt_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(txt_path,11))
    btn_txt_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Text_encrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Text_encrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(AES_path,12))
    btn_AES_path.grid(column=5, row=3)

    path_PVT_label = tkinter.Label(Text_encrypt, text="Private Key", font="Raleway")
    path_PVT_label.grid(column=1, row=5)

    PVT_path = tkinter.Entry(Text_encrypt, width=50)
    PVT_path.grid(column=3, row=5)

    btn_PVT_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(PVT_path,13))
    btn_PVT_path.grid(column=5, row=5)

    btn_submit_encrypt = tkinter.Button(Text_encrypt, text="Submit", command=lambda: text_encrypt_func())
    btn_submit_encrypt.grid(column=3, row=7)

def decryptText():
    Text_decrypt = Toplevel(Application)
    Text_decrypt.minsize(width=500, height=300)
    Text_decrypt.title("Decrypt Text")
    Text_decrypt.columnconfigure([0,2,4,6], minsize=20)
    Text_decrypt.rowconfigure([0,2,4,6,8], minsize=20)

    # browse field
    path_txt_label = tkinter.Label(Text_decrypt, text="AES encrypt", font="Raleway")
    path_txt_label.grid(column=1, row=1)

    txt_path = tkinter.Entry(Text_decrypt, width=50)
    txt_path.grid(column=3, row=1)

    btn_txt_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(txt_path,21))
    btn_txt_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Text_decrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Text_decrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(AES_path,22))
    btn_AES_path.grid(column=5, row=3)

    path_PUB_label = tkinter.Label(Text_decrypt, text="Public Key", font="Raleway")
    path_PUB_label.grid(column=1, row=5)

    PUB_path = tkinter.Entry(Text_decrypt, width=50)
    PUB_path.grid(column=3, row=5)

    btn_PUB_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(PUB_path,23))
    btn_PUB_path.grid(column=5, row=5)

    path_DS_label = tkinter.Label(Text_decrypt, text="Digital Signature", font="Raleway")
    path_DS_label.grid(column=1, row=7)

    DS_path = tkinter.Entry(Text_decrypt, width=50)
    DS_path.grid(column=3, row=7)

    btn_DS_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(DS_path,24))
    btn_DS_path.grid(column=5, row=7)

    btn_submit_decrypt = tkinter.Button(Text_decrypt, text="Submit", command=lambda: text_decrypt_func())
    btn_submit_decrypt.grid(column=3, row=9)

def modeTextfile():

    Text_window = Toplevel(Application)
    Text_window.minsize(width=500, height=300)
    Text_window.title("Encrypt & Decrypt Text")
    
    Text_window.columnconfigure([0,1],minsize=250)
    Text_window.rowconfigure([0,1,2], minsize=100)

    text_logo = tkinter.PhotoImage(file= "material/temp/text_logo_small.png")
    text_logo_label = tkinter.Label(Text_window, image=text_logo)
    text_logo_label.grid(column=0, row=0)

    btn_AES = tkinter.Button(Text_window, text="Generate AES KEY", font="Raleway", bg="#8d6c9f", fg="white", command=generateAESkey)
    btn_AES.grid(column=0, row=1)

    btn_RSA = tkinter.Button(Text_window, text="Generate RSA KEY", font="Raleway", bg="#8d6c9f", fg="white", command=generateRSAkey)
    btn_RSA.grid(column=0, row=2)

    btn_Tutorial = tkinter.Button(Text_window, text="Tutorial", font="Raleway", bg="#8d6c9f", fg="white", command=tutorialText)
    btn_Tutorial.grid(column=1, row=0)

    btn_Encrypt = tkinter.Button(Text_window, text="Encrypt", font="Raleway", bg="#8d6c9f", fg="white", command=encryptText)
    btn_Encrypt.grid(column=1, row=1)

    btn_Decrypt = tkinter.Button(Text_window, text="Decrypt", font="Raleway", bg="#8d6c9f", fg="white", command=decryptText)
    btn_Decrypt.grid(column=1, row=2)

def tutorialPicture():
    Picture_tutorial = Toplevel(Application)
    Picture_tutorial.minsize(width=500, height=300)
    my_text = tkinter.Label(Picture_tutorial)
    my_text.pack(side=tkinter.LEFT, fill=BOTH, expand=True)

    tt_file = "material/temp/Tutorial_Encrypt_Decrypt_picture.txt"
    tfile = open(tt_file, 'r')
    stuff = tfile.read()
    print(stuff)
    my_text.configure(text=stuff)

def picture_encrypt_func():

    filedircache = "material/cache/cache_P_encrypt"
    with open(filedircache, 'r')as f:
        Picturefile = f.read()
    
    filedircache = "material/cache/cache_APE"
    with open(filedircache, 'r')as f:
        AES_pic1 = f.read()

    print("Picture_path : ",Picturefile)
    print("AES key: ",AES_pic1)
    encrypt_picture(Picturefile, AES_pic1)
    

def picture_decrypt_func():
    
    filedircache = "material/cache/cache_P_decrypt"
    with open(filedircache, 'r')as f:
        Picture_encrypt = f.read()
    
    filedircache = "material/cache/cache_APD"
    with open(filedircache, 'r')as f:
        AES_pic2 = f.read()

    print("Picture_encrypt_path : ",Picture_encrypt)
    print("AES key: ",AES_pic2)
    decrypt_picture(Picture_encrypt, AES_pic2)

def encryptPicture():
    Picture_encrypt = Toplevel(Application)
    Picture_encrypt.minsize(width=500, height=300)
    Picture_encrypt.title("Encrypt Picture")
    Picture_encrypt.columnconfigure([0,2,4,6], minsize=20)
    Picture_encrypt.rowconfigure([0,2,4,6], minsize=20)

    # browse field
    path_Picture_label = tkinter.Label(Picture_encrypt, text="Picture [.png]", font="Raleway")
    path_Picture_label.grid(column=1, row=1)

    Picture_path = tkinter.Entry(Picture_encrypt, width=50)
    Picture_path.grid(column=3, row=1)

    btn_Picture_path = tkinter.Button(Picture_encrypt, text="Browse", command=lambda: set_path(Picture_path,31))
    btn_Picture_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Picture_encrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Picture_encrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Picture_encrypt, text="Browse", command=lambda: set_path(AES_path,32))
    btn_AES_path.grid(column=5, row=3)

    btn_submit = tkinter.Button(Picture_encrypt, text="Submit", command=lambda: picture_encrypt_func())
    btn_submit.grid(column=3, row=5)

def decryptPicture():
    Picture_decrypt = Toplevel(Application)
    Picture_decrypt.minsize(width=500, height=300)
    Picture_decrypt.title("Decrypt Picture")
    Picture_decrypt.columnconfigure([0,2,4,6], minsize=20)
    Picture_decrypt.rowconfigure([0,2,4,6], minsize=20)

    # browse field
    path_Picture_label = tkinter.Label(Picture_decrypt, text="Picture encrypt", font="Raleway")
    path_Picture_label.grid(column=1, row=1)

    Picture_path = tkinter.Entry(Picture_decrypt, width=50)
    Picture_path.grid(column=3, row=1)

    btn_Picture_path = tkinter.Button(Picture_decrypt, text="Browse", command=lambda: set_path(Picture_path,41))
    btn_Picture_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Picture_decrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Picture_decrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Picture_decrypt, text="Browse", command=lambda: set_path(AES_path,42))
    btn_AES_path.grid(column=5, row=3)

    btn_submit = tkinter.Button(Picture_decrypt, text="Submit", command=lambda: picture_decrypt_func())
    btn_submit.grid(column=3, row=5)

def modePicturefile():
    Picture_window = Toplevel(Application)
    Picture_window.minsize(width=400, height=400)
    Picture_window.title("Encrypt & Decrypt Picture")
    Picture_window.columnconfigure([0,1],minsize=250)
    Picture_window.rowconfigure([0,1,2], minsize=100)

    btn_AES = tkinter.Button(Picture_window, text="Generate AES KEY", font="Raleway", bg="#8d6c9f", fg="white", command=generateAESkey)
    btn_AES.grid(column=0, row=1)

    btn_Tutorial = tkinter.Button(Picture_window, text="Tutorial", font="Raleway", bg="#8d6c9f", fg="white", command=tutorialPicture)
    btn_Tutorial.grid(column=1, row=0)

    btn_Encrypt = tkinter.Button(Picture_window, text="Encrypt", font="Raleway", bg="#8d6c9f", fg="white", command=encryptPicture)
    btn_Encrypt.grid(column=1, row=1)

    btn_Decrypt = tkinter.Button(Picture_window, text="Decrypt", font="Raleway", bg="#8d6c9f", fg="white", command=decryptPicture)
    btn_Decrypt.grid(column=1, row=2)

Application = tkinter.Tk()
Application.title("Application")
canvas = tkinter.Canvas(Application, width=500, height=300)
canvas.grid(columnspan=3, rowspan=4)

logo = tkinter.PhotoImage(file = "material/temp/icon_logo_small.png")
logo_label = tkinter.Label(Application, image=logo)
logo_label.grid(row=0, column=1)

info = tkinter.Label(Application, text='" Select Mode You Want to Encrypt & Decrypt "', font="Raleway")
info.grid(columnspan=3, column=0, row=2)

btn_textfile = tkinter.Button(Application, text="Text File", font="Raleway", bg="#8d6c9f", fg="white", width=10, height=2, command=modeTextfile)
btn_textfile.grid(column=0, row=1)

btn_picturefile = tkinter.Button(Application, text="Picture File", font="Raleway", bg="#8d6c9f", fg="white", width=10, height=2, command=modePicturefile)
btn_picturefile.grid(column=2, row=1)

Application.mainloop()
