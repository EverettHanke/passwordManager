import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import secrets
import string


backend = default_backend()
salt = b"2444"

def kdf():
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


def genPassword(length: int) -> str:
    return "".join(
        (
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for i in range(length)
        )
    )


# database code
with sqlite3.connect("password_Manager.db") as db:
    cursor = db.cursor()

cursor.execute("""CREATE TABLE IF NOT EXISTS masterpassword(id INTEGER PRIMARY KEY,password TEXT NOT NULL,recoveryKey TEXT NOT NULL);""")

cursor.execute("""CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY,website TEXT NOT NULL,username TEXT NOT NULL,password TEXT NOT NULL);""")

cursor.execute("""CREATE TABLE IF NOT EXISTS masterkey(id INTEGER PRIMARY KEY,masterKeyPassword TEXT NOT NULL,masterKeyRecoveryKey TEXT NOT NULL);""")


#*************************************************************
# BASIC POPUP FUNCTION
#*************************************************************
def popUp(text):
    input = simpledialog.askstring("input string", text)
    return input


#*************************************************************
# INITIATE WINDOW
#*************************************************************
window = Tk()
window.update()

window.title("Password Manager")

#*************************************************************
# HASH PASSWORD //note refractored to work now :)
#*************************************************************
def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

#*************************************************************
# SET MASTER PASSWORD //note refractored to work now :)
#*************************************************************
def firstTimeScreen(hasMasterKey=None):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")
    lblEntry = Label(window, text="Choose a Master Password")
    lblEntry.config(anchor=CENTER)
    lblEntry.pack()

    txtPasswordEntry = Entry(window, width=20, show="*")
    txtPasswordEntry.pack()
    txtPasswordEntry.focus()

    lblReEntry = Label(window, text="Re-enter password")
    lblReEntry.config(anchor=CENTER)
    lblReEntry.pack()

    txtPasswordReEntry = Entry(window, width=20, show="*")
    txtPasswordReEntry.pack()

    lblError = Label(window)
    lblError.config(anchor=CENTER)
    lblError.pack()

    #*********************************************************
    # SAVE PASSWORD (note: this function is nested)
    #*********************************************************
    def savePassword():
        if txtPasswordEntry.get() == txtPasswordReEntry.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txtPasswordEntry.get().encode())
            key = str(uuid.uuid4().hex)
            hashedRecoveryKey = hashPassword(key.encode())

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (hashedRecoveryKey)))

            # Check if masterkey exists, if it does replace it by encrypting it with new password hash, and new recoverykey hash
            # if it does not, generate a masterkey and encrypt it with new password hash, and new recoverykey hash
            masterKey = hasMasterKey if hasMasterKey else genPassword(64)
            cursor.execute("SELECT * FROM masterkey")
            if cursor.fetchall():
                cursor.execute("DELETE FROM masterkey WHERE id = 1")

            insert_masterkey = """INSERT INTO masterkey(masterKeyPassword, masterKeyRecoveryKey)
            VALUES(?, ?) """
            cursor.execute(
                insert_masterkey,
                (
                    (encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(txtPasswordEntry.get().encode())))),
                    (encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(key.encode())))),
                ),
            )

            # change encryptionKey to masterKey unencrypted by masterpassword
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey.encode()))

            db.commit()

            recoveryScreen(key)
        else:
            lblError.config(text="Passwords dont match")

    btnSubmit = Button(window, text="Save", command=savePassword)
    btnSubmit.pack(pady=5)

#*************************************************************
# RECOVERY SCREEN //note refractored to work now :)
#*************************************************************
def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")
    lblInstructions = Label(window, text="Save this key to be able to recover account")
    lblInstructions.config(anchor=CENTER)
    lblInstructions.pack()

    lblUserKey = Label(window, text=key)
    lblUserKey.config(anchor=CENTER)
    lblUserKey.pack()

    def copyKey():
        pyperclip.copy(lblUserKey.cget("text"))

    btnCopy = Button(window, text="Copy Key", command=copyKey)
    btnCopy.pack(pady=5)

    def done():
        vaultScreen()

    btnDone = Button(window, text="Done", command=done)
    btnDone.pack(pady=5)

#*************************************************************
# RESET PASSWORD SCREEN //note refractored to work now :)
#*************************************************************
def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")
    lblInstruction = Label(window, text="Enter Recovery Key")
    lblInstruction.config(anchor=CENTER)
    lblInstruction.pack()

    txtKeyEntry = Entry(window, width=20)
    txtKeyEntry.pack()
    txtKeyEntry.focus()

    lblError = Label(window)
    lblError.config(anchor=CENTER)
    lblError.pack()
    #*********************************************************
    # GET RECOVERY KEY (note: this function is nested)
    #*********************************************************
    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txtKeyEntry.get()).encode())
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?",[(recoveryKeyCheck)],)
        return cursor.fetchall()
    #*********************************************************
    # CHECK RECOVERY KEY (note: this function is nested)
    #*********************************************************
    def checkRecoveryKey():
        recoveryKey = getRecoveryKey()

        if recoveryKey:
            # unencrypt masterKey and pass it to firstTimeScreen
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            if masterKeyEntry:
                masterKeyRecoveryKey = masterKeyEntry[0][2]          
                
                masterKey = decrypt(masterKeyRecoveryKey, base64.urlsafe_b64encode(kdf().derive(str(txtKeyEntry.get()).encode()))).decode()

                firstTimeScreen(masterKey)
            else:
                print("Master Key entry missing!")
                exit()
        else:
            txtKeyEntry.delete(0, "end")
            lblError.config(text="Key is Invalid")

    btnSubmit = Button(window, text="Check Key", command=checkRecoveryKey)
    btnSubmit.pack(pady=5)

#*************************************************************
# LOGIN SCREEN //note refractored to work now :)
#*************************************************************
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")

    lblInstructions = Label(window, text="Enter  Master Password")
    lblInstructions.config(anchor=CENTER)
    lblInstructions.pack()

    txtEntry = Entry(window, width=20, show="*")
    txtEntry.pack()
    txtEntry.focus()

    lblError = Label(window)
    lblError.config(anchor=CENTER)
    lblError.pack(side=TOP)

    #*********************************************************
    # GET MASTER PASSWORD (note: this function is nested)
    #*********************************************************
    def getMasterPassword():
        checkHashedPassword = hashPassword(txtEntry.get().encode())

        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?",[(checkHashedPassword)],)
        return cursor.fetchall()
    
    #*********************************************************
    # CHECK PASSWORD (note: this function is nested)
    #*********************************************************
    def checkPassword():
        password = getMasterPassword()

        if password:
            # change encryptionKey to masterKey unencrypted by masterpassword
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            if masterKeyEntry:
                masterKeyPassword = masterKeyEntry[0][1]          

                print(txtEntry.get().encode())
                
                masterKey = decrypt(masterKeyPassword, base64.urlsafe_b64encode(kdf().derive(txtEntry.get().encode())))  

                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey))

                vaultScreen()
            else:
                print("Master Key entry missing!")
                exit()
        else:
            txtEntry.delete(0, "end")
            lblError.config(text="Wrong Password")

    #*********************************************************
    # RESET PASSWORD ROUTE (note: this function is nested)
    #*********************************************************
    def resetPassword():
        resetScreen()

    btnSubmit = Button(window, text="Submit", command=checkPassword)
    btnSubmit.pack(pady=5)

    btnResetPassword = Button(window, text="Reset Password", command=resetPassword)
    btnResetPassword.pack(pady=5)

#*************************************************************
# MAIN VAULT SCREEN
#*************************************************************
def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    #*********************************************************
    # ADD ENTRY (note: this function is nested)
    #*********************************************************
    def addEntry():
        prompt1 = "Website"
        prompt2 = "Username"
        prompt3 = "Password"
        prompt1 = encrypt(popUp(prompt1).encode(), encryptionKey)
        username = encrypt(popUp(prompt2).encode(), encryptionKey)
        password = encrypt(popUp(prompt3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website, username, password) VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (prompt1, username, password))
        db.commit()

        vaultScreen()
    #*********************************************************
    # REMOVE ENTRY (note: this function is nested)
    #*********************************************************
    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    window.geometry("750x550")
    window.resizable(height=None, width=None)
    lblTitle = Label(window, text="Password Manager", font=("Helvetica", 16))
    lblTitle.grid(column=1)

    btnAdd = Button(window, text="Add Password", command=addEntry)
    btnAdd.grid(column=1, pady=10)

    lblWeb = Label(window, text="Website")
    lblWeb.grid(row=2, column=0, padx=80)
    lblEmail = Label(window, text="Email")
    lblEmail.grid(row=2, column=1, padx=80)
    lblPass = Label(window, text="Password")
    lblPass.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if cursor.fetchall() != None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            lblWebData = Label(window,text=(decrypt(array[i][1], encryptionKey)),font=("Helvetica", 12),)
            lblWebData.grid(column=0, row=(i + 3))

            lblEmailData = Label(window,text=(decrypt(array[i][2], encryptionKey)),font=("Helvetica", 12),)
            lblEmailData.grid(column=1, row=(i + 3))

            #decrypt password and store as a variable
            password = decrypt(array[i][3], encryptionKey)
            
            lblPassData = Label(window,text=("********"),font=("Helvetica", 12),)
            lblPassData.grid(column=2, row=(i + 3))
            
            #create a delete button
            btnDelete = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btnDelete.grid(column=3, row=(i + 3), pady=10)
            #create a copy button
            btnCopy = Button(window, text="Copy", command=partial(pyperclip.copy, password.decode()))
            btnCopy.grid(column=4, row=(i + 3), pady=10)

            #TODO: Create an Update Password button here:

            #TODO: Create a Show Password Button here:
            def togglePassword(lbl, password):
                if(lbl.cget("text") == password):
                    lbl.config(text="********")
                else:
                    lbl.config(text=password)
            
            btnShow = Button(window, text="Show", command=partial(togglePassword, lblPassData, password.decode()))
            btnShow.grid(column=5, row=(i + 3), pady=10)
                
            

            #increment i
            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


#*************************************************************
# MAIN WINDOW CODE
#*************************************************************
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()