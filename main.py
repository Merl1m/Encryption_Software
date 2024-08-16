# Encryption & Decryption Software
# Version 1.1

'''
This is a python 3 script to encrypt and decrypt files using a password.
Install the requirements and test this script out for yourselves.
'''

# Import Section
from os import listdir, path
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from base64 import b64encode
from shutil import move
from sys import argv
from hashlib import sha256

# Classes
class Encrypt:
    def __init__(self, Path, KEY):
        self.Path = Path
        self.KEY = KEY
        self.Crypt = Fernet(KEY)
        self.Files = list()
        self.enc_c, self.err_c = 0, 0
        with open(Forbidden, 'rb') as File_Obj:
            Tmp = File_Obj.read()
        self.forbidden_hash = sha256(Tmp).hexdigest()
    def Encrypt_File(self, FILE):
        with open(FILE, 'rb') as File_Obj:
            Data = File_Obj.read()
        Enc_Data = self.Crypt.encrypt(Data)
        with open(FILE, 'wb') as File_Obj:
            File_Obj.write(Enc_Data)
        New_File_Name = FILE + '.encrypted'
        move(FILE, New_File_Name)

    def Recurse_Dir(self, PATH):
        if path.isfile(PATH):
            if not PATH.endswith(".encrypted"):
                self.Files.append(PATH)
        elif path.isdir(PATH):
            for item in listdir(PATH):
                Abs_Path = path.join(PATH, item)
                self.Recurse_Dir(Abs_Path)
    
    def Check_Forbidden(self, FILE):
        with open(FILE, 'rb') as File_Obj:
            Data = File_Obj.read()
        if sha256(Data).hexdigest() == self.forbidden_hash:
            return True
        else:
            return False
    
    def Execute(self):
        self.Recurse_Dir(self.Path)
        for File in self.Files:
            try:
                if self.Check_Forbidden(File) != True:
                    self.Encrypt_File(File)
                    self.enc_c += 1
            except PermissionError as Error:
                print(f"[-] {File} Not Encrypted | No Permission ")
                self.err_c += 1
        print(f"[*] Status [*]\n[+] Files Successfully Encrypted : {self.enc_c}\n[-] Files Not Encrypted : {self.err_c}")

class Decrypt:
    def __init__(self, Path, KEY):
        self.Path = Path
        self.KEY = KEY
        self.Crypt = Fernet(KEY)
        self.Files = list()
        self.dec_c, self.err_c = 0, 0
    
    def Recurse_Dir(self, PATH):
        if path.isfile(PATH):
            if PATH.endswith(".encrypted"):
                self.Files.append(PATH)
        elif path.isdir(PATH):
            for item in listdir(PATH):
                Abs_Path = path.join(PATH, item)
                self.Recurse_Dir(Abs_Path)

    def Decrypt_File(self, FILE):
        with open(FILE, 'rb') as File_Obj:
            Enc_Data = File_Obj.read()
        try:
            Dec_Data = self.Crypt.decrypt(Enc_Data)
            with open(FILE, 'wb') as File_Obj:
                File_Obj.write(Dec_Data)
            New_File_Name = FILE[0:-10]
            move(FILE, New_File_Name)
            self.dec_c += 1
        except InvalidSignature:
            print("[-] {FILE} Could not be decrypted due to invalid KEY")
            self.err_c += 1
    
    def Execute(self):
        self.Recurse_Dir(self.Path)
        for File in self.Files:
            self.Decrypt_File(File)
        print(f"[*] Status [*]\n[+] Files Successfully Decrypted : {self.dec_c}\n[-] Files Not Decrypted : {self.err_c}")

# Function
def Make_Key(PASSWORD):
    while len(PASSWORD) < 32:
        PASSWORD += "0"
    return b64encode(PASSWORD.encode())

# Variables and Main
Forbidden = argv[0]

if __name__=="__main__":
    while True:
        Target = str(input('Enter Path: '))
        if not path.exists(Target):
            print("[-] Path doesn't Exist!! ")
            continue
        break

    while True:
        Mode = str(input("Encryption or Decryption? [E/D]: "))
        if Mode != 'E' and Mode != 'D':
            print("[*] please choose E or D")
            continue
        Password = str(input("Enter a password (length max 32): "))
        if len(Password) > 32:
            print("[-] password length exceeded 32 characters!!")
            continue
        break

    Key = Make_Key(Password)
    if Mode == 'E':
        Cryptor = Encrypt(Target, Key)
    else:
        Cryptor = Decrypt(Target, Key)
    Cryptor.Execute()
