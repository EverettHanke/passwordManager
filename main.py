import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog, Toplevel
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

#*********************************************
# DATABASE CODE
#*********************************************
backend = default_backend()
salt = b'2444'
# kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
encryptionKey = 0
def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

with sqlite3.connect("passwords.db") as db:
    cursor = db.cursor()

#create a masterpassword datatable
cursor.execute("""CREATE TABLE IF NOT EXISTS masterpassword(id INTEGER PRIMARY KEY, password TEXT NOT NULL, recoveryKey TEXT NOT NULL);""")
#create a passwordVault datatable
cursor.execute("""CREATE TABLE IF NOT EXISTS passwordVault(id INTEGER PRIMARY KEY, website TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL);""")

#*********************************************
# CREATE POPUP WINDOW
#*********************************************
def popUp(text):
    #ToDo: Have it ask for the website, email, and password all in one and return an array instead.
    answer = simpledialog.askstring("Input String", text) #, parent=popup)
    return answer


#*********************************************
# INITIATE WINDOW
#*********************************************

window = Tk()
window.title("Password Manager")
#icon_path = "icon.ico" # FIX THIS LINE TO WORK WITH ICON
#window.iconbitmap(icon_path)  # FIX THIS LINE TO WORK WITH ICON

#*********************************************
# HASHING SCRIPT
#*********************************************
def hashPassword(password):
    hash = hashlib.sha256(password)
    hash = hash.hexdigest()
    return hash


#*********************************************
# LOGIN/SIGN IN/MAIN SCREEN
#*********************************************

# page that allows users to create a master password
def createMasterPassword():
    window.geometry("350x150")
    
    lbl = Label(window, text="Enter your password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txtEntry = Entry(window, width=20, show="*")
    txtEntry.pack()
    txtEntry.focus()

    lblReEnter = Label(window, text="Re-enter your password")
    lblReEnter.pack()

    txtReEntry = Entry(window, width=20, show="*")
    txtReEntry.pack()

    lblError = Label(window)
    lblError.pack()

    def savePassword():
        if(txtEntry.get() == txtReEntry.get()):

            sql = "DELETE FROM masterpassword WHERE id = 1" #if we have an existing masterpassword we must remove it

            cursor.execute(sql)

            hashedPassword = hashPassword(txtEntry.get().encode('utf-8'))

            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = derive_key(txtEntry.get()) #encryptionKey = base64.urlsafe_b64encode(derive_key(txtEntry.get()))


            print("Password saved")
            insert_pass = """INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)"""
            cursor.execute(insert_pass, [(hashedPassword),(recoveryKey)])
            db.commit()
            recoveryKeyScreen(key)
        else:
            lblError.config(text="Passwords do not match")


    btnSubmit = Button(window, text="Save", command=savePassword)
    btnSubmit.pack(pady=10)

def recoveryKeyScreen(key):
    #clear old window
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")
    
    lbl = Label(window, text="Save this key somewhere safe. You will need it to recover your password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lblKey = Label(window, text=key)
    lblKey.pack()

    def copyKey():
        pyperclip.copy(key)
        print("Key copied to clipboard")
    
    def loginScreen():
        mainScreen()

    btnCopyKey = Button(window, text="Copy Key", command=copyKey)
    btnCopyKey.pack(pady=10)

    btnContinue = Button(window, text="Continue", command=loginScreen)
    btnContinue.pack(pady=10)



def resetPasswordScreen():
    # Clear old window
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")
    
    lbl = Label(window, text="Enter your recovery key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txtEntry = Entry(window, width=20)
    txtEntry.pack()
    txtEntry.focus()

    lblError = Label(window)
    lblError.config(anchor=CENTER)
    lblError.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(txtEntry.get().encode('utf-8'))
        cursor.execute("SELECT recoveryKey FROM masterpassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchone()

    def checkRecoveryKey():
        checked = getRecoveryKey()
        if checked:
            # Fetch existing password data
            cursor.execute("SELECT id, website, email, password FROM passwordVault")
            existing_data = cursor.fetchall()
            
            # Decrypt existing data using the old encryption key
            decrypted_data = [
                (
                    row[0],
                    decrypt(row[1], encryptionKey).decode(),
                    decrypt(row[2], encryptionKey).decode(),
                    decrypt(row[3], encryptionKey).decode()
                )
                for row in existing_data
            ]
            
            # Prompt for new master password
            createMasterPassword()
            
            # Re-encrypt data with the new encryption key
            for row in decrypted_data:
                new_website = encrypt(row[1].encode(), encryptionKey)
                new_email = encrypt(row[2].encode(), encryptionKey)
                new_password = encrypt(row[3].encode(), encryptionKey)
                cursor.execute(
                    "UPDATE passwordVault SET website = ?, email = ?, password = ? WHERE id = ?",
                    (new_website, new_email, new_password, row[0])
                )
            db.commit()
        else:
            txtEntry.delete(0, 'end')
            lblError.config(text="Incorrect recovery key")

    btnSubmit = Button(window, text="Submit", command=checkRecoveryKey)
    btnSubmit.pack(pady=10)




# login screen function
def loginScreen():
    #clear old window
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")
    
    lbl = Label(window, text="Enter your password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txtEntry = Entry(window, width=20, show="*")
    txtEntry.pack()
    txtEntry.focus()

    lblError = Label(window)
    lblError.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txtEntry.get().encode('utf-8'))
        
        #print(checkHashedPassword)
        global encryptionKey
        encryptionKey = derive_key(txtEntry.get()) #encryptionKey = base64.urlsafe_b64encode(kdf.derive(txtEntry.get().encode()))

        cursor.execute("SELECT password FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchone()

    def checkPassword():
        match = getMasterPassword()
        if match:
            print("Correct password")
            mainScreen()
        else:
            txtEntry.delete(0,'end') #deletes the old text in the entry box
            print("Incorrect password")
            lblError.config(text="Incorrect password") #display error message
            pass

    def resetPassword():
        resetPasswordScreen()

    btnSubmit = Button(window, text="Submit", command=checkPassword)
    btnSubmit.pack(pady=10)

    btnReset = Button(window, text="Reset Password", command=resetPassword)
    btnReset.pack(pady=10)


def recalibrateEncryptionKey():
    # Fetch existing password data
    cursor.execute("SELECT id, website, email, password FROM passwordVault")
    existing_data = cursor.fetchall()
    
    # Decrypt existing data using the old encryption key
    decrypted_data = [
        (
            row[0],
            decrypt(row[1], encryptionKey).decode(),
            decrypt(row[2], encryptionKey).decode(),
            decrypt(row[3], encryptionKey).decode()
        )
        for row in existing_data
    ]
    # Re-encrypt data with the new encryption key
    for row in decrypted_data:
        new_website = encrypt(row[1].encode(), encryptionKey)
        new_email = encrypt(row[2].encode(), encryptionKey)
        new_password = encrypt(row[3].encode(), encryptionKey)
        cursor.execute(
            "UPDATE passwordVault SET website = ?, email = ?, password = ? WHERE id = ?",
            (new_website, new_email, new_password, row[0])
        )
    db.commit()


# main screen function
def mainScreen():
    #clear old window
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        txt1 = "Website"
        txt2 = "Email"
        txt3 = "Password"
        
        website = encrypt(popUp(txt1).encode(), encryptionKey)
        email = encrypt(popUp(txt2).encode(), encryptionKey)
        password = encrypt(popUp(txt3).encode(), encryptionKey)

        insert_fields = """INSERT INTO passwordVault(website, email, password) VALUES(?, ?, ?)"""
        cursor.execute(insert_fields, [(website), (email), (password)])
        db.commit()

        mainScreen()

    def deleteEntry(input):
        cursor.execute("DELETE FROM passwordVault WHERE id = ?", (input,))
        db.commit()
        mainScreen()

    window.geometry("700x350")
    lbl = Label(window, text="Password Manager")
    lbl.grid(column=1)

    btnAddPass = Button(window, text="Add Password", command=addEntry)
    btnAddPass.grid(column=1, pady=10)

    lblGridWeb = Label(window, text="Website")
    lblGridWeb.grid(row=2, column=0, padx=80)

    lblGridEmail = Label(window, text="Email")
    lblGridEmail.grid(row=2, column=1, padx=80)

    lblGridPass = Label(window, text="Password")
    lblGridPass.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM passwordVault")
    array = cursor.fetchall()  # Fetch all data once

    if array:  # Check if array is not empty
        for i, row in enumerate(array):
            lblWebRes = Label(window, text=(decrypt(row[1], encryptionKey)).decode(), font=("Helvetica", 12))
            lblWebRes.grid(column=0, row=i+3)

            lblEmailRes = Label(window, text=(decrypt(row[2], encryptionKey)).decode(), font=("Helvetica", 12))
            lblEmailRes.grid(column=1, row=i+3)

            lblPassRes = Label(window, text=(decrypt(row[3], encryptionKey)).decode(), font=("Helvetica", 12))
            lblPassRes.grid(column=2, row=i+3)

  

    

# display window
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
   loginScreen()
else:
    createMasterPassword()
window.mainloop()