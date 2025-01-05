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
from tkinter import ttk

#set theme:
#style = ttk.Style()
#style.theme_use('clam') 
#note: if we use a style we would have to change label and button to their counterparts in the style such as ttk.ttk.Button and ttk.ttk.Label

#backend encryuption:
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
# INITIATE WINDOW
#*************************************************************
window = Tk()
window.update()

window.title("Password Manager")

# Initializing style
style = ttk.Style()
style.theme_use('clam') 

# Define custom colors
primary_color = "#2c2f33"  # Dark gray
secondary_color = "#23272a"  # Darker gray
accent_color = "#7289da"    # Hover blue
text_color = "#ffffff"      # White text

# Configure the style
style.configure(
    "TLabel",
    background=primary_color,
    foreground=text_color,
    font=("Helvetica", 12),
)
style.configure("TButton",background=secondary_color,foreground=text_color,borderwidth=1,padding=5,relief="flat",font=("Helvetica", 10, "bold"),)
style.map("TButton",background=[("active", accent_color)],foreground=[("active", "#ffffff")],)
style.configure("TEntry",fieldbackground=secondary_color,foreground=text_color,insertbackground=text_color,  # Cursor colorborderwidth=1,
font=("Helvetica", 12),
)
# Set the root window background color
window.configure(bg=primary_color)
# Set the app icon
window.iconbitmap("images/lock.ico")


#*************************************************************
# HASH PASSWORD //note refractored to work now :)
#*************************************************************
def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash


#*************************************************************
# BASIC POPUP FUNCTION
#*************************************************************
def popUp(text):
    def on_submit():
        nonlocal user_input  # Use a nonlocal variable to store the value
        user_input = entry.get()
        popup.destroy()

    def on_cancel():
        nonlocal user_input
        user_input = None
        popup.destroy()
    
    user_input = None
    popup = Toplevel()
    popup.title("Input")
    popup.geometry("300x150")
    popup.configure(bg=primary_color)  # Match the primary background color
    popup.iconbitmap("images/fingerprint.ico")

    popup_label = ttk.Label(popup, text=text, style="TLabel")
    popup_label.pack(pady=10)

    entry = ttk.Entry(popup, width=30)
    entry.pack(pady=5)
    entry.focus()

    button_frame = ttk.Frame(popup, style="TFrame")
    button_frame.pack(pady=10)

    submit_btn = ttk.Button(button_frame, text="Submit", command=on_submit)
    submit_btn.pack(side=LEFT, padx=5, pady=5)

    cancel_btn = ttk.Button(button_frame, text="Cancel", command=on_cancel)
    cancel_btn.pack(side=RIGHT, padx=5, pady=5)

    popup.transient(window)  # Make the popup modal
    popup.grab_set()
    window.wait_window(popup)


    return user_input



#*************************************************************
# SET MASTER PASSWORD //note refractored to work now :)
#*************************************************************
def firstTimeScreen(hasMasterKey=None):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("300x300")
    lblEntry = ttk.Label(window, text="Choose a Master Password")
    lblEntry.config(anchor=CENTER)
    lblEntry.pack()

    txtPasswordEntry = ttk.Entry(window, width=20, show="*")
    txtPasswordEntry.pack()
    txtPasswordEntry.focus()

    lblReEntry = ttk.Label(window, text="Re-enter password")
    lblReEntry.config(anchor=CENTER)
    lblReEntry.pack()

    txtPasswordReEntry = ttk.Entry(window, width=20, show="*")
    txtPasswordReEntry.pack()

    lblError = ttk.Label(window)
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

    btnSubmit = ttk.Button(window, text="Save", command=savePassword)
    btnSubmit.pack(pady=5)

#*************************************************************
# RECOVERY SCREEN //note refractored to work now :)
#*************************************************************
def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")
    lblInstructions = ttk.Label(window, text="Save this key to be able to recover account")
    lblInstructions.config(anchor=CENTER)
    lblInstructions.pack()

    lblUserKey = ttk.Label(window, text=key)
    lblUserKey.config(anchor=CENTER)
    lblUserKey.pack()

    def copyKey():
        pyperclip.copy(lblUserKey.cget("text"))

    btnCopy = ttk.Button(window, text="Copy Key", command=copyKey)
    btnCopy.pack(pady=5)

    def done():
        vaultScreen()

    btnDone = ttk.Button(window, text="Done", command=done)
    btnDone.pack(pady=5)

#*************************************************************
# RESET PASSWORD SCREEN //note refractored to work now :)
#*************************************************************
def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")
    lblInstruction = ttk.Label(window, text="Enter Recovery Key")
    lblInstruction.config(anchor=CENTER)
    lblInstruction.pack()

    txtKeyEntry = ttk.Entry(window, width=20)
    txtKeyEntry.pack()
    txtKeyEntry.focus()

    lblError = ttk.Label(window)
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

    btnSubmit = ttk.Button(window, text="Check Key", command=checkRecoveryKey)
    btnSubmit.pack(pady=5)

#*************************************************************
# LOGIN SCREEN //note refractored to work now :)
#*************************************************************
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("300x300")

    lblInstructions = ttk.Label(window, text="Enter  Master Password")
    lblInstructions.config(anchor=CENTER)
    lblInstructions.pack()

    txtEntry = ttk.Entry(window, width=20, show="*")
    txtEntry.pack()
    txtEntry.focus()

    lblError = ttk.Label(window)
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

    btnSubmit = ttk.Button(window, text="Submit", command=checkPassword)
    btnSubmit.pack(pady=5)

    btnResetPassword = ttk.Button(window, text="Reset Password", command=resetPassword)
    btnResetPassword.pack(pady=5)

#*************************************************************
# MAIN VAULT SCREEN
#*************************************************************
def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.iconbitmap("images/unlock.ico")

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

    window.geometry("1250x750")
    window.resizable(height=None, width=None)
    lblTitle = ttk.Label(window, text="Password Manager", font=("Helvetica", 16))
    lblTitle.grid(column=1)

    btnAdd = ttk.Button(window, text="Add Password", command=addEntry)
    btnAdd.grid(column=1, pady=10)

    lblWeb = ttk.Label(window, text="Website")
    lblWeb.grid(row=2, column=0, padx=80)
    lblEmail = ttk.Label(window, text="Email")
    lblEmail.grid(row=2, column=1, padx=80)
    lblPass = ttk.Label(window, text="Password")
    lblPass.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if cursor.fetchall() != None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            lblWebData = ttk.Label(window,text=(decrypt(array[i][1], encryptionKey)),font=("Helvetica", 12),)
            lblWebData.grid(column=0, row=(i + 3))

            lblEmailData = ttk.Label(window,text=(decrypt(array[i][2], encryptionKey)),font=("Helvetica", 12),)
            lblEmailData.grid(column=1, row=(i + 3))

            #decrypt password and store as a variable
            password = decrypt(array[i][3], encryptionKey)

            lblPassData = ttk.Label(window,text=("********"),font=("Helvetica", 12),)
            lblPassData.grid(column=2, row=(i + 3))
            
            #create a delete button
            btnDelete = ttk.Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btnDelete.grid(column=6, row=(i + 3), pady=10, padx=10) #note: changing column to 6 puts it at the very end of the row
            #create a copy button
            btnCopy = ttk.Button(window, text="Copy", command=partial(pyperclip.copy, password.decode()))
            btnCopy.grid(column=4, row=(i + 3), pady=10, padx=10)

            #*********************************************************
            # UPDATE PASSWORD (note: this function is nested) 
            #*********************************************************
            def updatePassword(entry_ID):
                newPass = popUp("Enter new password")
                if(newPass):
                    newPass = encrypt(newPass.encode(), encryptionKey)
                    cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (newPass, entry_ID))
                    db.commit()
                    vaultScreen()
            
            btnUpdate = ttk.Button(window, text="Update", command=partial(updatePassword, array[i][0]))
            btnUpdate.grid(column=5, row=(i + 3), pady=10, padx=10)

            #*********************************************************
            # TOGGLE PASSWORD (note: this function is nested)
            #*********************************************************
            def togglePassword(lbl, password):
                if(lbl.cget("text") == password):
                    lbl.config(text="********")
                else:
                    lbl.config(text=password)

            #Show password button
            btnShow = ttk.Button(window, text="Show", command=partial(togglePassword, lblPassData, password.decode()))
            btnShow.grid(column=3, row=(i + 3), pady=10, padx=10) #note: changing column to 3 puts it at the very front of the row

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