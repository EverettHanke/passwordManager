#import sqlite3, hashlib
from tkinter import *

window = Tk()

window.title("Password Manager")

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
        if(txtEntry == txtReEntry):
            print("Password saved")
            pass
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

    def checkPassword():
        password = "test"
        #print(password)
        if password == txtEntry.get():
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
    window.geometry("700x350")

    lbl = Label(window, text="Password Manager")
    

# display window
createMasterPassword()
window.mainloop()