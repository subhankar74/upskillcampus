from tkinter import *
from tkinter import ttk
import tkinter as tk
from db_operation import DbOperations
import sqlite3
import hashlib
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# database
with sqlite3.connect("pass.db") as db:
    cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoverykey TEXT NOT NULL);
""")

class root_root:
    
    def __init__(self,root,db):
        
        self.db=db
        self.root=root
        cursor.execute("SELECT * FROM masterpassword")
        if cursor.fetchall():
            self.loginScreen()
        else:
            self.firstScreen()
        
    def hashPassword(self,input):
        hash1 = hashlib.sha256(input)
        hash1 = hash1.hexdigest()

        return hash1
    
    def firstScreen(self):
        for widget in root.winfo_children():
            widget.destroy()
        root.title("PassWord_SignUP_Screen")
        root.geometry("250x150")
        lbl=Label(root,text="Create Master PassWord")
        lbl.config(anchor=CENTER)
        lbl.pack()
    
        txt=Entry(root,width=20,bg="paleturquoise",font=("Ariel",10))
        txt.pack()
        txt.focus()
        
        lbl1=Label(root,text="Re-enter PassWord")
        lbl1.pack()
        
        txt1=Entry(root,width=20,bg="paleturquoise",font=("Ariel",10),show="*")
        txt1.pack()
        txt1.focus()
        lbl2=Label(root)
        lbl2.pack()
        def savepass():
            if txt.get()==txt1.get():
                sql = "DELETE FROM masterpassword WHERE id = 1"

                cursor.execute(sql)

                hashedPassword = self.hashPassword(txt.get().encode('utf-8'))
                key = str(uuid.uuid4().hex)
                recoveryKey = self.hashPassword(key.encode('utf-8'))
                
                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
            
                insert_password = """INSERT INTO masterpassword(password, recoveryKey)
                VALUES(?, ?) """
                cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
                db.commit()
                self.recoveryScreen(key)
            else:
                lbl2.config(text="PassWord do not match")
        btn=Button(root,text="Save",command=savepass,width=10,bg="lime")
        btn.pack(pady=5)
        
    def recoveryScreen(self,key):
        for widget in root.winfo_children():
            widget.destroy()

        root.geometry('250x125')
        lbl = Label(root, text="Save This Key to Recover Your Account")
        lbl.config(anchor=CENTER)
        lbl.pack()

        lbl1 = Label(root, text=key)
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        def copyKey():
            pyperclip.copy(lbl1.cget("text"))

        btn = Button(root, text="Copy Key", command=copyKey,bg="spring green")
        btn.pack(pady=5)

        def done():
            self.passwordvault()

        btn = Button(root, text="Done", command=done,bg="cyan2")
        btn.pack(pady=5)
            
    def resetScreen(self):
        for widget in root.winfo_children():
            widget.destroy()

        root.geometry('250x125')
        lbl = Label(root, text="Enter Recovery Key")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(root, width=20,bg="paleturquoise",show="*")
        txt.pack()
        txt.focus()

        lbl1 = Label(root)
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        def getRecoveryKey():
            recoveryKeyCheck = self.hashPassword(str(txt.get()).encode('utf-8'))
            cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
            return cursor.fetchall()

        def checkRecoveryKey():
            checked = getRecoveryKey()

            if checked:
                self.firstScreen()
            else:
                txt.delete(0, 'end')
                lbl1.config(text='Wrong Key')

        btn = Button(root, text="Check Key", command=checkRecoveryKey,bg="medium spring green")
        btn.pack(pady=5)
    
    def loginScreen(self):
        for widget in root.winfo_children():
            widget.destroy()
        root.title("PassWord_Login_Screen")
        root.geometry("250x125")
        lbl=Label(root,text="Enter Master PassWord")
        lbl.config(anchor=CENTER)
        lbl.pack()
    
        txt=Entry(root,width=20,bg="paleturquoise",font=("Ariel",10),show="*")
        txt.pack()
        txt.focus()
    
        lbl1=Label(root)
        lbl1.config(anchor=CENTER)
        lbl1.pack(side=TOP)
        def getmasterpassword():
            checkHashedPassword = self.hashPassword(txt.get().encode('utf-8'))
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
            cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?",[(checkHashedPassword)])
            return cursor.fetchall()
        def checkpassword():
            match=getmasterpassword()
            if match:
                self.passwordvault()
            else:
                txt.delete(0,'end')
                lbl1.config(text="Wrong PassWord")  

        def resetPassword():
            self.resetScreen()
        # 
        btn=Button(root,text="Submit",command=checkpassword,width=10,bg="turquoise1")
        btn.pack(pady=2)
        
        btn = Button(root, text="Reset Password", command=resetPassword,bg="spring green")
        btn.pack(pady=2)
        
        
    def passwordvault(self):
        for widget in root.winfo_children():
            widget.destroy()
        self.root.title("PassWord_Manager_Vault")
        self.root.geometry("900x600+40+40")
        head_title=Label(self.root, text="PassWord_Manager",width=40,bg="turquoise2",font=("Ariel",20),padx=10,pady=10,justify=CENTER,anchor="center").grid(columnspan=4,padx=140,pady=10)
        self.crud_frame=Frame(self.root,highlightbackground="black",highlightthickness=1,padx=10,pady=30)
        self.crud_frame.grid()
        self.create_entry_labels()
        self.create_entry_boxes()
        self.create_crud_buttons()
        
        self.create_recods_tree()
         
    def create_entry_labels(self):
        self.col_no,self.row_no=0, 0
        labels_info=('ID','Website','UserName','PassWord')
        for label_info in labels_info:
            Label(self.crud_frame,text=label_info,bg='grey',fg='white',font=('Ariel',12),padx=5,pady=2).grid(row=self.row_no,column=self.col_no,padx=5,pady=2)
            self.col_no+=1
    def create_crud_buttons(self):
        self.row_no+=1
        self.col_no=0
        buttons_info=(('Save','green',self.save_record),('Update','blue',self.update_record),('Delete','red',self.delete_record),('Copy_Password','cyan',self.copy_password),('Show_All_Records','lightgreen',self.show_record))  
        for btn_info in buttons_info:
            if btn_info[0]=='Show_All_Records':
                self.row_no+=1
                self.col_no=0
            Button(self.crud_frame,text=btn_info[0],bg=btn_info[1],fg='white',font=('Ariel',12),padx=2,pady=1,width=15,command=btn_info[2]).grid(row=self.row_no,column=self.col_no,padx=5,pady=6)
            self.col_no+=1
            
    def create_entry_boxes(self):
        self.row_no+=1
        self.entry_boxes=[]
        self.col_no=0
        for i in range(4):
            show=""
            if i==3:
                show="*"
            entry_box=Entry(self.crud_frame,width=22,background="paleturquoise",font=("Arial",12),show=show)
            entry_box.grid(row=self.row_no,column=self.col_no,padx=5,pady=2)
            self.col_no+=1
            self.entry_boxes.append(entry_box)
    
    def save_record(self):
        website=self.entry_boxes[1].get()
        username=self.entry_boxes[2].get()
        password=self.entry_boxes[3].get()
        data={'website':website,'username':username,'password':password}
        self.db.create_record(data)
        self.show_record()
           
    def update_record(self):
        ID=self.entry_boxes[0].get()
        website=self.entry_boxes[1].get()
        username=self.entry_boxes[2].get()
        password=self.entry_boxes[3].get()
        data={'ID':ID,'website':website,'username':username,'password':password}
        self.db.update_record(data)
        self.show_record()
    
    def delete_record(self):
        ID=self.entry_boxes[0].get()
        self.db.delete_record(ID)
        self.show_record()
    
    def show_record(self):
        for item in self.records_tree.get_children():
            self.records_tree.delete(item)
        record_list=self.db.show_records() 
        for record in record_list:
            self.records_tree.insert('',END,values=(record[0],record[3],record[4],record[5]))
            
    def create_recods_tree(self):
        columns=('ID','Website','Username','Password')
        self.records_tree=ttk.Treeview(self.root,columns=columns,show='headings')
        self.records_tree.heading('ID',text="ID")
        self.records_tree.heading('Website',text="Website Name")
        self.records_tree.heading('Username',text="Username")
        self.records_tree.heading('Password',text="Password")
        self.records_tree['displaycolumns']=('Website','Username')
        
        def item_selected(event):
            for selected_item in self.records_tree.selection():
                item=self.records_tree.item(selected_item)
                record=item['values']
                for entry_box, item in zip(self.entry_boxes,record):
                    entry_box.delete(0,END)
                    entry_box.insert(0,item)
        self.records_tree.bind('<<TreeviewSelect>>',item_selected)
        self.records_tree.grid() 
    # copy to clipboard
    def copy_password(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.entry_boxes[3].get())
        message="Password Copied"
        title="Copy"
        if self.entry_boxes[3].get()=="":
            message="Box is Empty"
            title="Error"
        self.showmessage(title,message)
    def showmessage(self,title_box:str=None,message:str=None):
        TIME_TO_WAIT=900
        root=Toplevel(self.root)
        background="green"
        if title_box=="Error":
            background="red"
        root.geometry('200x30+600+200')
        root.title(title_box)
        Label(root,text=message,background=background,font=("Ariel",15),fg='white').pack(padx=4,pady=2)
        try:
            root.after(TIME_TO_WAIT,root.destroy)
        except Exception as e:
            print("Error Occured".e)
      
if __name__=="__main__":
    db_class=DbOperations()
    db_class.create_table()
    root=Tk()
    root_class=root_root(root,db_class)
    root.mainloop()
            