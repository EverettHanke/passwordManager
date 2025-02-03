import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import secrets
import string
from tkinter import ttk
import tkinter as tk
import os
import sys

#*************************************************************
# RESOURCE PATH
#*************************************************************
def resource_path(relative_path):
    """ Get the absolute path to the resource (including .ico files). """
    try:
        # PyInstaller creates a temp folder and stores the path to the app in sys._MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)
#*************************END OF RESOURCE PATH****************


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
style.configure("TLabel",background=primary_color,foreground=text_color,font=("Helvetica", 12),)
style.configure("TButton",background=secondary_color,foreground=text_color,borderwidth=1,padding=5,relief="flat",font=("Helvetica", 10, "bold"),)
style.map("TButton",background=[("active", accent_color)],foreground=[("active", "#ffffff")],)
style.configure("TEntry",fieldbackground=secondary_color,foreground=text_color,insertbackground=text_color,  # Cursor colorborderwidth=1,
font=("Helvetica", 12),)
#Scroll Bar Styling
style.configure("Vertical.TScrollbar",background=secondary_color,troughcolor=primary_color,arrowcolor=text_color, bordercolor=secondary_color,)
style.map("Vertical.TScrollbar",background=[("active", accent_color)],arrowcolor=[("active", accent_color)],)

style.configure("Horizontal.TScrollbar",background=secondary_color,troughcolor=primary_color,arrowcolor=text_color,bordercolor=secondary_color,)
style.map("Horizontal.TScrollbar",background=[("active", accent_color)],arrowcolor=[("active", accent_color)],)
# Set the root window background color
window.configure(bg=primary_color)
# Set the app icon
window.iconbitmap(resource_path("requirements/images/lock.ico"))


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
    popup.iconbitmap(resource_path("requirements/images/fingerprint.ico"))

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

            insert_password = """INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (hashedRecoveryKey)))

            # Check if masterkey exists, if it does replace it by encrypting it with new password hash, and new recoverykey hash
            # if it does not, generate a masterkey and encrypt it with new password hash, and new recoverykey hash
            masterKey = hasMasterKey if hasMasterKey else genPassword(64)
            cursor.execute("SELECT * FROM masterkey")
            if cursor.fetchall():
                cursor.execute("DELETE FROM masterkey WHERE id = 1")

            insert_masterkey = """INSERT INTO masterkey(masterKeyPassword, masterKeyRecoveryKey) VALUES(?, ?) """
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

    window.geometry("350x250")
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
        vaultScreen("")

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

                vaultScreen("")
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

def vaultScreen(where):
    # Clear existing widgets
    for widget in window.winfo_children():
        widget.destroy()

    # Set window properties
    window.geometry("1250x750")
    window.resizable(height=True, width=True)
    window.iconbitmap(resource_path("requirements/images/unlock.ico"))

    # Configure grid resizing
    window.grid_rowconfigure(0, weight=1)  # Make row 0 (canvas row) expandable
    window.grid_columnconfigure(0, weight=1)  # Make column 0 (canvas column) expandable
    window.grid_columnconfigure(1, weight=0)  # Scrollbar column doesn't need expansion

    # Create a canvas for scrolling
    canvas = Canvas(window, bg=primary_color, highlightthickness=0)
    scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg=primary_color)

    # Bind scrollable frame to canvas
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))  # Adjust scrollable region dynamically
    )

    # Create window on canvas and attach scrollable frame to canvas
    frame_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Place canvas and scrollbar in the window using grid
    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")

    # Center scrollable frame dynamically
    def center_scrollable_frame(event=None):
        canvas_width = canvas.winfo_width()
        frame_width = scrollable_frame.winfo_reqwidth()
        x_offset = (canvas_width - frame_width) // 2  # Calculate center
        canvas.coords(frame_id, x_offset, 0)  # Update frame position

    # Bind resize events
    canvas.bind("<Configure>", center_scrollable_frame)

    # Title (centered)
    lblTitle = ttk.Label(scrollable_frame, text="Password Manager", font=("Helvetica", 16))
    lblTitle.grid(column=3, row=0, pady=10)

    # Generate Random Password and Copy to Clipboard
    def generateRandomPassword():
        # Generate a random password (12 characters long, including uppercase, lowercase, digits, and symbols)
        password_length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(random.choice(characters) for _ in range(password_length))
        pyperclip.copy(random_password)  # Copy the password to clipboard
        print(f"Generated Password: {random_password}")  # For testing/debugging

    btnGeneratePassword = ttk.Button(scrollable_frame, text="Generate Random Password", command=generateRandomPassword)
    btnGeneratePassword.grid(column=3, pady=10, row=2, padx=20)

    lblCopy = ttk.Label(scrollable_frame, text="Copy", font=("Helvetica", 12, "bold"))
    lblCopy.grid(column=4, row=2, pady=10, padx=20)
    lblUpdate = ttk.Label(scrollable_frame, text="Update", font=("Helvetica", 12, "bold"))
    lblUpdate.grid(column=5, row=2, pady=10,padx=20)
    lblDel = ttk.Label(scrollable_frame, text="Delete", font=("Helvetica", 12, "bold"))
    lblDel.grid(column=6, row=2, pady=10,padx=20)

    # Add Entry Button
    def addEntry():
        website = encrypt(popUp("Website").encode(), encryptionKey)
        username = encrypt(popUp("Username").encode(), encryptionKey)
        password = encrypt(popUp("Password").encode(), encryptionKey)

        cursor.execute("INSERT INTO vault(website, username, password) VALUES(?, ?, ?)", (website, username, password))
        db.commit()
        vaultScreen("")

    btnAdd = ttk.Button(scrollable_frame, text="Add Password", command=addEntry)
    btnAdd.grid(column=3, pady=10, row=1)
    
    # Search Function
    def searchVault():
        search_query = searchEntry.get().strip()
        vaultScreen(search_query)  # Reload with search filter

    searchEntry = ttk.Entry(scrollable_frame, width=40)
    searchEntry.grid(column=0, row=1, columnspan=2, padx=10, pady=10)

    searchButton = ttk.Button(scrollable_frame, text="Search", command=searchVault)
    searchButton.grid(column=2, row=1, padx=10, pady=10)

    # Column labels (centered in grid)
    lblWeb = ttk.Label(scrollable_frame, text="Website", font=("Helvetica", 12, "bold"))
    lblWeb.grid(row=2, column=0, padx=20, pady=5)
    lblEmail = ttk.Label(scrollable_frame, text="Email", font=("Helvetica", 12, "bold"))
    lblEmail.grid(row=2, column=1, padx=20, pady=5)
    lblPass = ttk.Label(scrollable_frame, text="Password", font=("Helvetica", 12, "bold"))
    lblPass.grid(row=2, column=2, padx=20, pady=5)



    # Fetch and display data
    cursor.execute("SELECT * FROM vault")
    entries = cursor.fetchall()
    #print(entries)

    for i, entry in enumerate(entries):
        entry_id, website, username, password = entry
        decrypted_website = decrypt(website, encryptionKey).decode()
        decrypted_username = decrypt(username, encryptionKey).decode()
        decrypted_password = decrypt(password, encryptionKey).decode()

        # Skip entries that do NOT match the search if where is provided
        if where and where.lower() not in decrypted_website.lower() and where.lower() not in decrypted_username.lower():
            continue  # Skip this entry if no match is found

        # Website
        lblWebData = ttk.Label(scrollable_frame, text=decrypted_website, font=("Helvetica", 12))
        lblWebData.grid(column=0, row=i + 3, padx=10, pady=5)

        # Username
        lblEmailData = ttk.Label(scrollable_frame, text=decrypted_username, font=("Helvetica", 12))
        lblEmailData.grid(column=1, row=i + 3, padx=10, pady=5)

        # Password
        lblPassData = ttk.Label(scrollable_frame, text="********", font=("Helvetica", 12))
        lblPassData.grid(column=2, row=i + 3, padx=10, pady=5)

        # Toggle Password Function
        def togglePassword(lbl, password):
            lbl.config(text=password if lbl.cget("text") == "********" else "********")

        #show password function
        btnShow = ttk.Button(scrollable_frame, text="Show", command=lambda lbl=lblPassData, pw=decrypted_password: togglePassword(lbl, pw))
        btnShow.grid(column=3, row=i + 3, padx=10, pady=5)

        # Copy Password Function
        btnCopy = ttk.Button(scrollable_frame, text="Copy", command=lambda pw=decrypted_password: pyperclip.copy(pw))
        btnCopy.grid(column=4, row=i + 3, padx=10, pady=5)

        # Update Password Function
        def updatePassword(entry_id):
            new_password = popUp("Enter new password")
            if new_password:
                encrypted_new_password = encrypt(new_password.encode(), encryptionKey)
                cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (encrypted_new_password, entry_id))
                db.commit()
                vaultScreen("")

        btnUpdate = ttk.Button(scrollable_frame, text="Update", command=lambda id=entry_id: updatePassword(id))
        btnUpdate.grid(column=5, row=i + 3, padx=10, pady=5)

        # Remove Entry Function
        def removeEntry(entry_id):
            cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
            db.commit()
            vaultScreen("")

        btnDelete = ttk.Button(scrollable_frame, text="Delete", command=lambda id=entry_id: removeEntry(id))
        btnDelete.grid(column=6, row=i + 3, padx=10, pady=5)

    # Ensure content is centered within the canvas
    scrollable_frame.grid_rowconfigure(len(entries) + 3, weight=1)  # Allow content to expand vertically





#*************************************************************
# MAIN WINDOW CODE
#*************************************************************
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()