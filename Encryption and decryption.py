import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class EmployeeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypt & Decrypt")

        self.width = self.root.winfo_screenwidth()
        self.height = self.root.winfo_screenheight()
        self.root.geometry(f"{self.width}x{self.height}+0+0")

        # Set cybersecurity tool-like background color
        self.root.configure(bg="#1e1e1e")

        title = tk.Label(self.root, text="Password and Message Encryption/Decryption", bd=4, relief="raised", bg="#333333", fg="#00ff00", font=("Elephant", 40, "italic"))
        title.pack(side="top", fill="x")

        # Add frame
        addFrame = tk.Frame(self.root, bd=5, relief="ridge", bg="#333333")
        addFrame.place(width=self.width/3, height=self.height-180, x=70, y=100)

        supBtn = tk.Button(addFrame, command=self.supFrameFun, text="Sign_Up", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 20, "bold"))
        supBtn.grid(row=0, column=0, padx=30, pady=60)

        sinBtn = tk.Button(addFrame, command=self.sinFrameFun, text="Sign_In", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 20, "bold"))
        sinBtn.grid(row=1, column=0, padx=30, pady=60)

        closeBtn = tk.Button(addFrame, text="Close", command=self.desMain, width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 20, "bold"))
        closeBtn.grid(row=2, column=0, padx=30, pady=60)

        # Detail frame
        self.detFrame = tk.Frame(self.root, bd=5, relief="ridge", bg="#333333")
        self.detFrame.place(width=self.width/2, height=self.height-180, x=self.width/3+140, y=100)

        title = tk.Label(self.detFrame, text="Person Details", bg="#333333", fg="#00ff00", font=("Elephant", 30, "bold"))
        title.pack(side="top", fill="x")

        self.tabFun()

        # Dictionary to store employee data
        self.employees = {}

        # Track if user is signed in
        self.signed_in = False

    def tabFun(self):
        tabFrame = tk.Frame(self.detFrame, bd=4, relief="sunken", bg="#1e1e1e")
        tabFrame.place(width=self.width/2-40, height=self.height-280, x=17, y=70)

        x_scrol = tk.Scrollbar(tabFrame, orient="horizontal")
        x_scrol.pack(side="bottom", fill="x")

        y_scrol = tk.Scrollbar(tabFrame, orient="vertical")
        y_scrol.pack(side="right", fill="y")

        self.table = ttk.Treeview(tabFrame, xscrollcommand=x_scrol.set, yscrollcommand=y_scrol.set,
                                  columns=("id", "name", "des", "addr", "pw"))

        x_scrol.config(command=self.table.xview)
        y_scrol.config(command=self.table.yview)

        self.table.heading("id", text="Employee_ID")
        self.table.heading("name", text="Employee_Name")
        self.table.heading("des", text="Designation")
        self.table.heading("addr", text="Employee_Addr")
        self.table.heading("pw", text="Passwords")
        self.table["show"] = "headings"

        self.table.pack(fill="both", expand=1)

    def supFrameFun(self):
        self.suFrame = tk.Frame(self.root, bd=4, relief="ridge", bg="#333333")
        self.suFrame.place(width=self.width/3, height=self.height-200, x=self.width/3+140, y=120)

        idLbl = tk.Label(self.suFrame, text="User_ID: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        idLbl.grid(row=0, column=0, padx=20, pady=25)
        self.id = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.id.grid(row=0, column=1, padx=10, pady=25)

        nameLbl = tk.Label(self.suFrame, text="User_Name: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        nameLbl.grid(row=1, column=0, padx=20, pady=25)
        self.name = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.name.grid(row=1, column=1, padx=10, pady=25)

        desLbl = tk.Label(self.suFrame, text="Designation: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        desLbl.grid(row=2, column=0, padx=20, pady=25)
        self.des = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.des.grid(row=2, column=1, padx=10, pady=25)

        addrLbl = tk.Label(self.suFrame, text="Address: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        addrLbl.grid(row=3, column=0, padx=20, pady=25)
        self.addr = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.addr.grid(row=3, column=1, padx=10, pady=25)

        pwLbl = tk.Label(self.suFrame, text="Password: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        pwLbl.grid(row=4, column=0, padx=20, pady=25)
        self.pw = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.pw.grid(row=4, column=1, padx=10, pady=25)

        keyLbl = tk.Label(self.suFrame, text="Encryption Key: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        keyLbl.grid(row=5, column=0, padx=20, pady=25)
        self.key = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.key.grid(row=5, column=1, padx=10, pady=25)

        okBtn = tk.Button(self.suFrame, command=self.signUpFun, text="SignUp", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 20, "bold"))
        okBtn.grid(row=6, column=0, padx=30, pady=30, columnspan=2)

    def desFrame(self):
        self.suFrame.destroy()

    def signUpFun(self):
        id = self.id.get()
        name = self.name.get()
        des = self.des.get()
        addr = self.addr.get()
        pw = self.pw.get()
        key = self.key.get()

        if id and name and des and addr and pw and key:
            id_int = int(id)

            encrypted = self.encrypt(pw, key)
            self.employees[id_int] = {
                "name": name,
                "des": des,
                "addr": addr,
                "pw": encrypted,
                "key": key,
                "messages": []
            }

            tk.messagebox.showinfo("Success", f"Employee {name} Registered Successfully!")
            self.desFrame()

            self.table.delete(*self.table.get_children())
            self.table.insert('', tk.END, values=(id_int, name, des, addr, encrypted))
        else:
            tk.messagebox.showerror("Error", "Please Fill All Input Fields!")

    def sinFrameFun(self):
        self.suFrame = tk.Frame(self.root, bd=4, relief="ridge", bg="#333333")
        self.suFrame.place(width=self.width/3, height=self.height-350, x=self.width/3+140, y=120)

        idLbl = tk.Label(self.suFrame, text="User_ID: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        idLbl.grid(row=0, column=0, padx=20, pady=25)
        self.idin = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.idin.grid(row=0, column=1, padx=10, pady=25)

        pwLbl = tk.Label(self.suFrame, text="Password: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        pwLbl.grid(row=1, column=0, padx=20, pady=25)
        self.pwin = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.pwin.grid(row=1, column=1, padx=10, pady=25)

        keyLbl = tk.Label(self.suFrame, text="Encryption Key: ", bg="#333333", fg="#00ff00", font=("Arial", 15, "bold"))
        keyLbl.grid(row=2, column=0, padx=20, pady=25)
        self.keyin = tk.Entry(self.suFrame, width=18, bd=2, font=("Arial", 15, "bold"))
        self.keyin.grid(row=2, column=1, padx=10, pady=25)

        okBtn = tk.Button(self.suFrame, command=self.sinFun, text="SignIn", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 20, "bold"))
        okBtn.grid(row=3, column=0, padx=30, pady=30, columnspan=2)

    def sinFun(self):
        id = int(self.idin.get())
        pw = self.pwin.get()
        key = self.keyin.get()

        if id in self.employees:
            decrypted = self.decrypt(self.employees[id]["pw"], key)
            if pw == decrypted:
                tk.messagebox.showinfo("Success", f"Welcome Mr/Mrs. {self.employees[id]['name']}")
                self.signed_in = True
                self.current_user_id = id
                self.current_key = key
                self.desFrame()
                self.table.delete(*self.table.get_children())
                self.table.insert('', tk.END, values=(id, self.employees[id]["name"], self.employees[id]["des"], self.employees[id]["addr"], self.employees[id]["pw"]))
                self.openMsgWindow()  # Open message encryption/decryption window
            else:
                tk.messagebox.showerror("Error", "Please Enter A Valid Employee Password or Key!")
        else:
            tk.messagebox.showerror("Error", "Please Enter A Valid Employee ID!")

    def openMsgWindow(self):
        if self.signed_in:
            self.msgWindow = tk.Toplevel(self.root)
            self.msgWindow.title("Message Encryption/Decryption")
            self.msgWindow.geometry("600x500")
            self.msgWindow.configure(bg="#1e1e1e")

            msgLbl = tk.Label(self.msgWindow, text="Enter Message: ", font=("Arial", 15, "bold"), bg="#1e1e1e", fg="#00ff00")
            msgLbl.grid(row=0, column=0, padx=20, pady=25)
            self.msg = tk.Text(self.msgWindow, width=50, height=5, bd=2, font=("Arial", 15, "bold"))
            self.msg.grid(row=0, column=1, padx=10, pady=25)

            encryptBtn = tk.Button(self.msgWindow, command=self.encryptMsg, text="Encrypt", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 15, "bold"))
            encryptBtn.grid(row=1, column=0, padx=30, pady=30, columnspan=2)

            decryptBtn = tk.Button(self.msgWindow, command=self.decryptMsg, text="Decrypt", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 15, "bold"))
            decryptBtn.grid(row=2, column=0, padx=30, pady=30, columnspan=2)

            self.resultLbl = tk.Label(self.msgWindow, text="", font=("Arial", 15, "bold"), bg="#1e1e1e", fg="#00ff00")
            self.resultLbl.grid(row=3, column=0, padx=20, pady=25, columnspan=2)
        else:
            tk.messagebox.showerror("Error", "Please Sign In First!")

    def encryptMsg(self):
        message = self.msg.get("1.0", tk.END).strip()
        if message:
            encrypted = self.encrypt(message, self.current_key)
            self.employees[self.current_user_id]["messages"].append(encrypted)
            self.showEncryptedMessage(encrypted)
        else:
            tk.messagebox.showerror("Error", "Please Enter A Message!")

    def decryptMsg(self):
        message = self.msg.get("1.0", tk.END).strip()
        if message:
            decrypted = self.decrypt(message, self.current_key)
            self.resultLbl.config(text=f"Decrypted: {decrypted}")
        else:
            tk.messagebox.showerror("Error", "Please Enter A Message!")

    def showEncryptedMessage(self, encrypted):
        self.encryptedWindow = tk.Toplevel(self.root)
        self.encryptedWindow.title("Encrypted Message")
        self.encryptedWindow.geometry("500x200")
        self.encryptedWindow.configure(bg="#1e1e1e")

        encryptedLbl = tk.Label(self.encryptedWindow, text="Encrypted Message:", font=("Arial", 15, "bold"), bg="#1e1e1e", fg="#00ff00")
        encryptedLbl.pack(pady=10)

        self.encryptedText = tk.Text(self.encryptedWindow, width=50, height=5, bd=2, font=("Arial", 15, "bold"))
        self.encryptedText.insert(tk.END, encrypted)
        self.encryptedText.pack(pady=10)

        copyBtn = tk.Button(self.encryptedWindow, command=self.copyEncryptedMessage, text="Copy", width=20, bd=3, relief="raised", bg="#00ff00", fg="#000000", font=("Arial", 15, "bold"))
        copyBtn.pack(pady=10)

    def copyEncryptedMessage(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.encryptedText.get("1.0", tk.END).strip())
        tk.messagebox.showinfo("Success", "Encrypted message copied to clipboard!")

    def encrypt(self, text, key):
        return ''.join(chr((ord(char) + int(key)) % 256) for char in text)

    def decrypt(self, text, key):
        return ''.join(chr((ord(char) - int(key)) % 256) for char in text)

    def clr(self, r, g, b):
        return f"#{r:02x}{g:02x}{b:02x}"

    def desMain(self):
        self.root.destroy()

root = tk.Tk()
obj = EmployeeApp(root)
root.mainloop()
