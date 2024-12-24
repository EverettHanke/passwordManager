import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog, Toplevel
from functools import partial

#*********************************************
# DATABASE CODE
#*********************************************
with sqlite3.connect("passwords.db") as db:
    cursor = db.cursor()

#create a masterpassword datatable
cursor.execute("""CREATE TABLE IF NOT EXISTS masterpassword(id INTEGER PRIMARY KEY, password TEXT NOT NULL);""")
#create a passwordVault datatable
cursor.execute("""CREATE TABLE IF NOT EXISTS passwordVault(id INTEGER PRIMARY KEY, website TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL);""")

#*********************************************
# CREATE POPUP WINDOW
#*********************************************
def popUp(text):
   # popup = Toplevel(window)
   # popup.lift()  # Bring the popup window to the front
   # popup.attributes('-topmost', True)  # Keep the popup window on top
   # popup.after_idle(popup.attributes, '-topmost', False)  # Allow other windows to be on top after the popup is closed
    answer = simpledialog.askstring("Input String", text) #, parent=popup)
    #popup.destroy()  # Destroy the popup after getting the input
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
    hash = hashlib.md5(password)
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

            hashedPassword = hashPassword(txtEntry.get().encode('utf-8'))
            print("Password saved")
            insert_pass = """INSERT INTO masterpassword(password) VALUES(?)"""
            cursor.execute(insert_pass, [(hashedPassword)])
            db.commit()
            mainScreen()
        else:
            lblError.config(text="Passwords do not match")


    btnSubmit = Button(window, text="Save", command=savePassword)
    btnSubmit.pack(pady=10)

# login screen function
def loginScreen():
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
        cursor.execute("SELECT password FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        #print(checkHashedPassword)
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

    btnSubmit = Button(window, text="Submit", command=checkPassword)
    btnSubmit.pack(pady=10)


# main screen function
def mainScreen():
    #clear old window
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        txt1 = "Website"
        txt2 = "Email"
        txt3 = "Password"
        
        website = popUp(txt1)
        email = popUp(txt2)
        password = popUp(txt3)

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
    if(cursor.fetchall()!= None):
        i = 0
        while(True):
            cursor.execute("SELECT * FROM passwordVault")
            array = cursor.fetchall()

            lblWebRes = Label(window, text=(array[i][1]), font=("Helvetica", 12))
            lblWebRes.grid(column=0, row=i+3)

            lblEmailRes = Label(window, text=(array[i][2]), font=("Helvetica", 12))
            lblEmailRes.grid(column=1, row=i+3)

            lblPassRes = Label(window, text=(array[i][3]), font=("Helvetica", 12))
            lblPassRes.grid(column=2, row=i+3)
            
            btnDel = Button(window, text="Delete", command=partial(deleteEntry, array[i][0]))
            btnDel.grid(row=i+3, column=3, pady=10)
            i = i+1

            cursor.execute("SELECT * FROM passwordVault")
            if(len(cursor.fetchall()) <= i):
                break


  

    

# display window
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
   loginScreen()
else:
    createMasterPassword()
window.mainloop()