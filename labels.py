from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save notes
def save_and_encrypt_notes():
    title = first_entry.get()
    message = secret_text.get("1.0",END)
    master_secret = second_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            first_entry.delete(0, END)
            second_entry.delete(0, END)
            secret_text.delete("1.0",END)

#decrypt notes

def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = second_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

window = Tk()
window.title("Tkinter Python")
window.minsize(width=300, height=500)
window.config(padx=20, pady=20)

image = PhotoImage(file="top_secret.png").subsample(7,7)
image_label = Label(window, image=image)
image_label.pack()

first_label = Label(window, text="Enter your title")
first_label.pack()

first_entry = Entry(window)
first_entry.pack()

second_label = Label(window, text="Enter your secret")
second_label.pack()

secret_text= Text(width=20,height=15)
secret_text.pack()

third_label = Label(window, text="Enter master key")
third_label.pack()

second_entry = Entry(window)
second_entry.pack()

first_button = Button(window, text="Save & Encrypt", command=save_and_encrypt_notes)
first_button.config(padx=5, pady=1)
first_button.pack(pady=5)

second_button = Button(window, text="Decrypt", command=decrypt_notes)
second_button.config(padx=5, pady=1)
second_button.pack()

window.mainloop()