import tkinter
from tkinter import filedialog

def set_path(entry_field):
    path = filedialog.askopenfilename()
    entry_field.delete(0, tkinter.END)
    entry_field.insert(0, path)

Application = tkinter.Tk()
Application.title("Application")
Application.geometry("400x500")

label_title = tkinter.Label(Application, text="Title")
label_title.pack()

txt_path = tkinter.Entry(Application, width=100)
txt_path.pack()

btn_path = tkinter.Button(Application, text="Select File", command=lambda: set_path(txt_path))
btn_path.pack()

Application.mainloop()