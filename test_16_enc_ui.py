import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
from tkinter import filedialog as fd
import tkinter.messagebox
import pyperclip
import base64

def onClick():
    tkinter.messagebox.showinfo(" ","Your text has been copied to the clipboard!")

def retrieve_input(text_widget):
    return text_widget.get("1.0","end-1c")

def generate_key():
    key = Fernet.generate_key()
    x = save_button()
    with open(x, 'wb') as file:
        file.write(key)
    
def save_button():
    files = [('Binary files', '*.DAT'),
             ('All Files', '*.*')]
    filepath = tk.filedialog.asksaveasfilename(filetypes=files, defaultextension=files)
    return filepath

def encrypt_text(key, og_string):
    f = Fernet(key)
    enc_str = f.encrypt(og_string)
    entry3.delete('1.0', 'end')
    entry3.insert('1.0', enc_str)
    test = enc_str.decode(('utf-8'))
    pyperclip.copy(test)
    onClick()

def decrypt_text(key, enc_string):
    f = Fernet(key)
    enc_str = f.decrypt(enc_string)
    entry3_2.delete('1.0', 'end')
    entry3_2.insert('1.0', enc_str)
    pyperclip.copy(str(enc_str))
    onClick()

user_key = None

def select_key(entry_number):
    filetypes = (
        ('Binary files', 'DAT'),
        ('All files', '*.*')
    )

    filename = fd.askopenfile(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    with open('encryption_key', 'rb'):
        global user_key
        user_key = filename.read()
    insert_key(entry_number)

def insert_key(enrty_number):
    enrty_number.delete(0, 'end')
    enrty_number.insert(0, user_key)

root = tk.Tk()
root.title("Encryptor App")
root.geometry('300x320')
tabControl = ttk.Notebook(root)

notebook = ttk.Notebook(root)

#TAB 1
tab1 = ttk.Frame(notebook, width=380, height=400)
tab1.grid()#fill='both', expand=True)
notebook.add(tab1, text='Encrypt')

label1 = tk.Label(tab1, text="Please, select the encryption key:")
label1.config(font=('Times New Roman', 14))
label1.grid(row=0,column=0,sticky="ns")
label1.grid_propagate(0)

button1 = tk.Button(tab1, text='Select', command=lambda: select_key(entry1))
button1.grid(row=1,column=0,sticky="ns")
button1.grid_propagate(0)

entry1 = tk.Entry(tab1,  width=50)
entry1.grid(row=2,column=0,sticky="ns")
entry1.grid_propagate(0)


label2 = tk.Label(tab1, text="Enter the text you want to encrypt:")
label2.config(font=('Times New Roman', 14))
label2.grid(row=3,column=0,sticky="ns")
label2.grid_propagate(0)

entry2 = tk.Text(tab1, width=37, height=5)
entry2.grid(row=4,column=0,sticky="ns")
entry2.grid_propagate(0)

button2 = tk.Button(tab1, text='Encrypt!', command=lambda: [encrypt_text(user_key, bytes(retrieve_input(entry2), 'utf-8')), insert_key(entry1)])
button2.grid(row=5,column=0,sticky="ns")
button2.grid_propagate(0)

entry3 = tk.Text(tab1, width=37, height=5)
entry3.grid(row=6,column=0,sticky="ns")
entry3.grid_propagate(0)

# TAB2
tab2 = ttk.Frame(notebook, width=380, height=400)
tab2.grid()
notebook.add(tab2, text='Decrypt')


label1_2 = tk.Label(tab2, text="Please, select the decryption key:")
label1_2.config(font=('Times New Roman', 14))
label1_2.grid(row=0,column=0,sticky="ns")
label1_2.grid_propagate(0)

button1_2 = tk.Button(tab2, text='Select', command=lambda: select_key(entry1_2))
button1_2.grid(row=1,column=0,sticky="ns")
button1_2.grid_propagate(0)

entry1_2 = tk.Entry(tab2,  width=50)
entry1_2.grid(row=2,column=0,sticky="ns")
entry1_2.grid_propagate(0)

label2_2 = tk.Label(tab2, text="Enter the text you want to decrypt:")
label2_2.config(font=('Times New Roman', 14))
label2_2.grid(row=3,column=0,sticky="ns")
label2_2.grid_propagate(0)

entry2_2 = tk.Text(tab2, width=37, height=5)
entry2_2.grid(row=4,column=0,sticky="ns")
entry2_2.grid_propagate(0)

button2_2 = tk.Button(tab2, text='Decrypt!', command=lambda: [decrypt_text(user_key, bytes(retrieve_input(entry2_2), 'utf-8')), insert_key(entry1_2)])
button2_2.grid(row=5,column=0,sticky="ns")
button2_2.grid_propagate(0)

entry3_2 = tk.Text(tab2, width=37, height=5)
entry3_2.grid(row=6,column=0,sticky="ns")
entry3_2.grid_propagate(0)


# TAB3

tab3 = ttk.Frame(notebook, width=380, height=400)
tab3.grid()
notebook.add(tab3, text='Generate Key')

label1_3 = tk.Label(tab3, text="Select the location for the  key:")
label1_3.config(font=('Times New Roman', 14))
label1_3.grid(row=0,column=0,sticky="N")
label1_3.grid_propagate(0)

button1_3 = tk.Button(tab3, text='Generate key', command=lambda: generate_key())
button1_3.grid(row=1,column=0,sticky="ns")
button1_3.grid_propagate(0)

notebook.pack()

root.mainloop()
