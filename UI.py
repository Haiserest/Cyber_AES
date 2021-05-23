import tkinter
from tkinter import Toplevel, filedialog
from tkinter import *
from PIL import Image

def set_path(entry_field):
    path = filedialog.askopenfilename()
    entry_field.delete(0, tkinter.END)
    entry_field.insert(0, path)
    print(path)

def tutorialText():
    Text_tutorial = Toplevel(Application)
    Text_tutorial.minsize(width=500, height=300)

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

    btn_txt_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(txt_path))
    btn_txt_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Text_encrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Text_encrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(AES_path))
    btn_AES_path.grid(column=5, row=3)

    path_PVT_label = tkinter.Label(Text_encrypt, text="Private Key", font="Raleway")
    path_PVT_label.grid(column=1, row=5)

    PVT_path = tkinter.Entry(Text_encrypt, width=50)
    PVT_path.grid(column=3, row=5)

    btn_PVT_path = tkinter.Button(Text_encrypt, text="Browse", command=lambda: set_path(PVT_path))
    btn_PVT_path.grid(column=5, row=5)

    btn_submit = tkinter.Button(Text_encrypt, text="Submit")
    btn_submit.grid(column=3, row=7)

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

    btn_txt_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(txt_path))
    btn_txt_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Text_decrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Text_decrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(AES_path))
    btn_AES_path.grid(column=5, row=3)

    path_PUB_label = tkinter.Label(Text_decrypt, text="Public Key", font="Raleway")
    path_PUB_label.grid(column=1, row=5)

    PUB_path = tkinter.Entry(Text_decrypt, width=50)
    PUB_path.grid(column=3, row=5)

    btn_PUB_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(PUB_path))
    btn_PUB_path.grid(column=5, row=5)

    path_DS_label = tkinter.Label(Text_decrypt, text="Digital Signature", font="Raleway")
    path_DS_label.grid(column=1, row=7)

    DS_path = tkinter.Entry(Text_decrypt, width=50)
    DS_path.grid(column=3, row=7)

    btn_DS_path = tkinter.Button(Text_decrypt, text="Browse", command=lambda: set_path(DS_path))
    btn_DS_path.grid(column=5, row=7)

    btn_submit = tkinter.Button(Text_decrypt, text="Submit")
    btn_submit.grid(column=3, row=9)

def modeTextfile():

    Text_window = Toplevel(Application)
    Text_window.minsize(width=500, height=300)
    Text_window.title("Encrypt & Decrypt Text")
    
    Text_window.columnconfigure([0,1],minsize=250)
    Text_window.rowconfigure([0,1,2], minsize=100)

    text_logo = tkinter.PhotoImage(file= "material/temp/text_logo_small.png")
    text_logo_label = tkinter.Label(Text_window, image=text_logo)
    text_logo_label.grid(column=0, row=0)

    btn_AES = tkinter.Button(Text_window, text="Generate AES KEY", font="Raleway", bg="#8d6c9f", fg="white")
    btn_AES.grid(column=0, row=1)

    btn_RSA = tkinter.Button(Text_window, text="Generate RSA KEY", font="Raleway", bg="#8d6c9f", fg="white")
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

    btn_Picture_path = tkinter.Button(Picture_encrypt, text="Browse", command=lambda: set_path(Picture_path))
    btn_Picture_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Picture_encrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Picture_encrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Picture_encrypt, text="Browse", command=lambda: set_path(AES_path))
    btn_AES_path.grid(column=5, row=3)

    btn_submit = tkinter.Button(Picture_encrypt, text="Submit")
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

    btn_Picture_path = tkinter.Button(Picture_decrypt, text="Browse", command=lambda: set_path(Picture_path))
    btn_Picture_path.grid(column=5, row=1)

    path_AES_label = tkinter.Label(Picture_decrypt, text="AES Key", font="Raleway")
    path_AES_label.grid(column=1, row=3)

    AES_path = tkinter.Entry(Picture_decrypt, width=50)
    AES_path.grid(column=3, row=3)

    btn_AES_path = tkinter.Button(Picture_decrypt, text="Browse", command=lambda: set_path(AES_path))
    btn_AES_path.grid(column=5, row=3)

    btn_submit = tkinter.Button(Picture_decrypt, text="Submit")
    btn_submit.grid(column=3, row=5)

def modePicturefile():
    Picture_window = Toplevel(Application)
    Picture_window.minsize(width=400, height=400)
    Picture_window.title("Encrypt & Decrypt Picture")
    Picture_window.columnconfigure([0,1],minsize=250)
    Picture_window.rowconfigure([0,1,2], minsize=100)

    btn_AES = tkinter.Button(Picture_window, text="Generate AES KEY", font="Raleway", bg="#8d6c9f", fg="white")
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

# # resize picture 
# image = Image.open('material/temp/.png')
# new_image = image.resize((80, 80))
# new_image.save('material/temp/_small.png')

info = tkinter.Label(Application, text='" Select Mode You Want to Encrypt & Decrypt "', font="Raleway")
info.grid(columnspan=3, column=0, row=2)

btn_textfile = tkinter.Button(Application, text="Text File", font="Raleway", bg="#8d6c9f", fg="white", width=10, height=2, command=modeTextfile)
btn_textfile.grid(column=0, row=1)

btn_picturefile = tkinter.Button(Application, text="Picture File", font="Raleway", bg="#8d6c9f", fg="white", width=10, height=2, command=modePicturefile)
btn_picturefile.grid(column=2, row=1)

Application.mainloop()
