import tkinter as tk
import customtkinter as ctk
from string import ascii_letters, digits
from random import choice
from cryptography.fernet import Fernet

class Manager_GUI:
    def __init__(self):
        
        # Window configuration
        self.window = ctk.CTk()
        self.window.geometry('850x500')
        self.window.resizable(False, False)
        self.theme = ctk.set_appearance_mode('Dark')
        self.window.title('Password Manager')

        # Widgets Creation
        self.main_title = ctk.CTkLabel(master=self.window, text='Password Manager', text_color='DodgerBlue', font=('Terminal', 20))
        
        # Main Canvas
        self.left_canvas = ctk.CTkCanvas(master=self.window, width=167, height=501, bg='black',highlightthickness=2, highlightbackground="black")
        self.central_canvas = ctk.CTkCanvas(master=self.window, width=450, height=200, bg='black', highlightbackground="black")

         # Widgets Place
        self.main_title.place(relx=0.60, rely=0.05, anchor=ctk.CENTER)
        self.left_canvas.place(relx=0, rely=0)
        

        # Buttons
        self.but_generate_pw = ctk.CTkButton(master=self.window, text='Generate Password', height=50, width=160, bg_color='black', command=self.button_pw)
        self.but_generate_key = ctk.CTkButton(master=self.window, text='Generate Key', height=50, width=160, bg_color='black', command=self.button_key)
        self.but_encrypt = ctk.CTkButton(master=self.window, text='Encrypt', height=50, width=160, bg_color='black', command=self.button_encrypt)
        self.but_decrypt = ctk.CTkButton(master=self.window, text='Decrypt', height=50, width=160, bg_color='black', command=self.button_decrypt)
        

       # Buttons Place
        self.but_generate_pw.place(relx=0.0055, rely=0.01)
        self.but_generate_key.place(relx=0.0055, rely=0.21)
        self.but_encrypt.place(relx=0.0055, rely=0.41)
        self.but_decrypt.place(relx=0.0055, rely=0.61)

        # Main Loop
        self.window.mainloop()




    # GENERATE PASSWORD
    def button_pw(self):
        # Destroy Canvas and Re-Create
        self.central_canvas.destroy()
        self.central_canvas = ctk.CTkCanvas(master=self.window, width=450, height=200, bg='black', highlightbackground="black")
        self.central_canvas.place(relx=0.33, rely=0.2)
        
        # Widgets Creation
        self.pw_output = ctk.CTkEntry(master=self.central_canvas, width=280)
        self.pw_label = ctk.CTkLabel(master=self.central_canvas, text='Choose the lenght and click submit (Default is 14)')
        self.but_generate_PW = ctk.CTkButton(master=self.central_canvas ,text='Generate Password', command=self.generate_pw)
        self.len_entry = ctk.CTkEntry(master=self.central_canvas, width=40)
        self.len_label = ctk.CTkLabel(master=self.central_canvas, text='Length:')


        # Widgets Placement
        self.pw_label.place(relx=0.5, rely=0.2, anchor=tk.CENTER)
        self.pw_output.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        self.but_generate_PW.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
        self.len_entry.place(relx=0.89, rely=0.8)
        self.len_label.place(relx= 0.75, rely=0.8)
        
    # Password Generator Logic
    def generate_pw(self):
        LEN = self.len_entry.get()
        if not LEN: LEN = 14
        self.pw_output = ctk.CTkEntry(master=self.central_canvas, width=280)
        self.pw_output.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        pw = ''
        chars = ascii_letters + digits + '!' + '@' + '#' + '$' + '%' + '&' + '*'
        for _ in range(int(LEN)):
            for c in choice(chars):
                pw += c
        self.pw_output.delete(0, 'end')
        self.pw_output.insert(0, pw)
        



    # GENERATE KEY
    def button_key(self):
        # Destroy Canvas and Re-Create
        self.central_canvas.destroy()
        self.central_canvas = ctk.CTkCanvas(master=self.window, width=450, height=200, bg='black', highlightbackground="black")
        self.central_canvas.place(relx=0.33, rely=0.2)


        # Canvas elements
        self.key_output = ctk.CTkEntry(master=self.central_canvas, width=380)
        self.generate_label = ctk.CTkLabel(master=self.central_canvas, text='Generate a random Key')

        # Submit Button
        self.but_submit = ctk.CTkButton(master=self.central_canvas, text='Generate Key', command=self.generate_key)
        self.but_submit.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    
        # Elements placement
        self.key_output.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        self.generate_label.place(relx=0.5, rely=0.2, anchor=tk.CENTER)
        
        
    def generate_key(self):
        # Generate the key and insert the output to the entry
        key = Fernet.generate_key()
        self.key_output.delete(0, 'end')
        self.key_output.insert(0, key)




    # ENCRYPT
    def button_encrypt(self):
        # Destroy Canvas and Re-Create
        self.central_canvas.destroy()
        self.central_canvas = ctk.CTkCanvas(master=self.window, width=450, height=350, bg='black', highlightbackground="black")
        self.central_canvas.place(relx=0.33, rely=0.2)

        # Canvas elements
        self.encrypt_label_1 = ctk.CTkLabel(master=self.central_canvas, text='Encrypt Password')
        self.encrypt_label_2 = ctk.CTkLabel(master=self.central_canvas, text='Password:')
        self.encrypt_label_3 = ctk.CTkLabel(master=self.central_canvas, text='Encryption Key:')
        self.encrypt_label_4 = ctk.CTkLabel(master=self.central_canvas, text='Encrypted Password:')
        self.encrypt_entry_1 = ctk.CTkEntry(master=self.central_canvas, width=280)
        self.encrypt_entry_2 = ctk.CTkEntry(master=self.central_canvas, width=300)
        self.but_encrypt_submit = ctk.CTkButton(master=self.central_canvas, text='Submit', command=self.encrypt)
        self.encryption_output = ctk.CTkEntry(master=self.central_canvas, width=400)


        # Elements placement
        self.encrypt_label_1.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
        self.encrypt_label_2.place(relx=0.1, rely=0.25, anchor=tk.CENTER)
        self.encrypt_label_3.place(relx=0.128, rely=0.35, anchor=tk.CENTER)
        self.encrypt_entry_1.place(relx=0.59, rely=0.25, anchor=tk.CENTER)
        self.encrypt_entry_2.place(relx=0.61, rely=0.35, anchor=tk.CENTER)
        self.but_encrypt_submit.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.encrypt_label_4.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
        self.encryption_output.place(relx=0.5, rely=0.8, anchor=tk.CENTER)

    def encrypt(self):
        pw = self.encrypt_entry_1.get()
        key = self.encrypt_entry_2.get()
        f = Fernet(key.encode())
        encrypted = f.encrypt(pw.encode())
        self.encryption_output.delete(0, 'end')
        self.encryption_output.insert(0, encrypted)
   
   
   
    # DECRYPT
    def button_decrypt(self):
        # Destroy Canvas and Re-Create
        self.central_canvas.destroy()
        self.central_canvas = ctk.CTkCanvas(master=self.window, width=450, height=350, bg='black', highlightbackground="black")
        self.central_canvas.place(relx=0.33, rely=0.2)

        # Canvas elements
        self.decrypt_label_1 = ctk.CTkLabel(master=self.central_canvas, text='Decrypt Password')
        self.decrypt_label_2 = ctk.CTkLabel(master=self.central_canvas, text='Password:')
        self.decrypt_label_3 = ctk.CTkLabel(master=self.central_canvas, text='Encryption Key:')
        self.decrypt_label_4 = ctk.CTkLabel(master=self.central_canvas, text='Decrypted Password:')
        self.decrypt_entry_1 = ctk.CTkEntry(master=self.central_canvas, width=280)
        self.decrypt_entry_2 = ctk.CTkEntry(master=self.central_canvas, width=300)
        self.but_decrypt_submit = ctk.CTkButton(master=self.central_canvas, text='Submit', command=self.decrypt)
        self.decryption_output = ctk.CTkEntry(master=self.central_canvas, width=400)


        # Elements placement
        self.decrypt_label_1.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
        self.decrypt_label_2.place(relx=0.1, rely=0.25, anchor=tk.CENTER)
        self.decrypt_label_3.place(relx=0.128, rely=0.35, anchor=tk.CENTER)
        self.decrypt_entry_1.place(relx=0.59, rely=0.25, anchor=tk.CENTER)
        self.decrypt_entry_2.place(relx=0.61, rely=0.35, anchor=tk.CENTER)
        self.but_decrypt_submit.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.decrypt_label_4.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
        self.decryption_output.place(relx=0.5, rely=0.8, anchor=tk.CENTER)


    def decrypt(self):
        pw = self.decrypt_entry_1.get().encode()
        key = self.decrypt_entry_2.get()
        f = Fernet(key)
        decrypted = f.decrypt(pw)
        self.decryption_output.delete(0, 'end')
        self.decryption_output.insert(0, decrypted)



Manager_GUI()
