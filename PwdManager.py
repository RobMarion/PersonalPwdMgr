#!/usr/bin/python3
# MIT License

# Copyright (c) 2023 Robert Marion

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import getpass
import hashlib
import time
import datetime
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import csv
import os
import re
import secrets
from hashlib import pbkdf2_hmac

# TODO: salt password file

class PwdManager:
    def __init__(self):
        self.__master_hash_password = False
        self.min_len_master_password = 8
        self.ENC_FILE_NAME = ".acct_file.cpt"
        self.BAD_LOGIN_ATTEMPTS = 0
        self.BAD_ATTEMPT_CEILING = 5
        self.DELAY = 1
        self.PWD_TIMEOUT = (5 * 60) # 5 minutes
        #time_expire()

    def get_password(self, uname, account_name=""):
        exclude_list = ['>','&',',','%','*']
        if not account_name: 
            account_name = input("Account name: ")
            if not account_name: return
            for char in exclude_list:
                if char in account_name:
                    print("Invalid account name")
                    return False
        if self.__get_master_password(uname):
            pt_file = self.decrypt_file()
            if pt_file:
                pt_file = str(pt_file)
                pt = pt_file.replace("\\n","\n")
                pt = pt.splitlines()
                for row in csv.reader(pt):
                    if row[0].casefold().find(account_name.casefold()) != -1:
                        print(f"{row[0]}: {row[1]}")
                        return row[1]
            else:
                return False
        else:
            return False

    def get_account_names(self,uname):
        if not self.__get_master_password(uname):
            print("Unable to decrypt")
        else:
            pt_file = self.decrypt_file()
            if pt_file:
                pt_file = str(pt_file)
                pt = pt_file.replace("\\n","\n")
                pt = pt.splitlines()
                for row in csv.reader(pt):
                    if str(row[0]): print(f"{row[0]}: Created: {row[2]}")
                    
    def __get_verify_password(self,uname):
        #if not self.__master_hash_password:
        pwd_0 = getpass.getpass("Password: ")
        p = PwdUtil()
        pwd_success = p.verify_user(uname, pwd_0)
        self.login_attempt(pwd_success)
        self.__master_hash_password = pwd_success #TODO set to a temporary token (possibly a prime) that is revoked
        return pwd_success

    def TODO__get_master_password(self,uname):
        #if not self.__master_hash_password:
        pwd_0 = getpass.getpass("Password: ")
        p = PwdUtil()
        pwd_success = p.verify_user(uname, pwd_0)
        self.login_attempt(pwd_success)
        self.__master_hash_password = pwd_success

    # TODO: Replace this with something that takes a username
    # AND GETS THE PWD FROM .pmgr file
    # AND WE ARENT USING THE UNAME YET
    def __get_master_password(self, uname):        
        if not self.__master_hash_password:
            pwd_0 = getpass.getpass("Password: ")
            self.__master_hash_password = hashlib.sha256(bytearray(pwd_0,'utf-8')).hexdigest()            
            del pwd_0   
        state = self.verify_master_password()
        if not state: 
            self.__master_hash_password = None
        time.sleep(self.DELAY) 
        return state

        
    def add_user_password(self,uname, pwd_0):
        p = PwdUtil()
        p.add_user(uname, pwd_0)
        
    def delete_user(self, uname, pwd_0):
        p = PwdUtil()
        return(p.delete_user(uname, pwd_0))
                    
    def encrypt_stream(self,p_str=""):
        self.__get_master_password()
        crypto = CryptoUtil()
        crypto.encrypt_file(self.__master_hash_password, p_str)
        del crypto
            
    def decrypt_file(self):
        self.__get_master_password()
        crypto = CryptoUtil()
        return(crypto.decrypt_file(self.__master_hash_password))
       
    def verify_master_password(self):
        try: 
            with open(".pmgr", encoding="utf8") as pwd_file: 
                inmem_hash = pwd_file.read()
        except:
            exit("Could not open password file.")
        ret_val = (inmem_hash.casefold() == self.__master_hash_password.casefold())
        self.login_attempt(ret_val)
        return ret_val    

    def add_account(self,uname, account_name):
        if not account_name: return False
        if not self.__get_master_password(uname):
            return False

        pt_file = self.decrypt_file()
        if pt_file: 
            pt_file = str(pt_file)
            pt_file = pt_file.replace("\\n","\n")
            pt_file = self.strip_bytechar(pt_file)
            pt_file = pt_file.rstrip("'")
            pt = pt_file.splitlines()
            
            for row in csv.reader(pt):
                if row[0].casefold().find(account_name.casefold()) != -1:
                    print(f"{row[0]} already exists")
                    return
        __pwd_0 = getpass.getpass(f"Password for {account_name}: ")
        if __pwd_0 != getpass.getpass("Confirm Password: "):
            time.sleep(self.DELAY)
            print("Passwords did not match")
            return
        current_date = str(datetime.date.today())
        if not pt_file:
            pt_file = f"{account_name},{__pwd_0},{current_date}"
        else:
            pt_file += f"\n{account_name},{__pwd_0},{current_date}"
        print(pt_file)
        self.encrypt_stream(pt_file)
        return True

    def delete_account(self,uname, account_name):
        if not account_name: return False
        if not self.__get_master_password(uname):
            return False
            
        pt_file = self.decrypt_file()
        if not pt_file:
            return False

        pt_file = str(pt_file)            
        pt_file = pt_file.replace("\\n","\n")
        pt_file = self.strip_bytechar(pt_file)        
        pt_file = pt_file.splitlines()      
        rows = ""
        for row in csv.reader(pt_file):
            if row[0].casefold().find(account_name.casefold()) == -1:
                rows = rows + row[0] +","+ row[1] + "," + row[2] + "\n"
        rows = rows.rstrip('\n')
        self.encrypt_stream(rows)
        return True
        
    def change_account_password(self, uname, account_name):
        ret_val = False
        if not self.__get_master_password(uname):
            return ret_val
        if self.delete_account(account_name):
            ret_val = self.add_account(account_name)
        return ret_val
        
    def change_master_password(self):
        pass
        
    def strip_bytechar(self,in_str):
        return in_str.replace("b'","")

    def login_attempt(self, success):
        if success:
            self.BAD_LOGIN_ATTEMPTS = 0
            self.DELAY = 1
        else:
            self.BAD_LOGIN_ATTEMPTS += 1
            if self.BAD_LOGIN_ATTEMPTS >= self.BAD_ATTEMPT_CEILING: 
                self.DELAY = 10

    #TODO
    def time_expire(self):
        """Nulls out the password after a set amount of time"""
        pass
       
class CryptoUtil:
    """This class separates out the encrypt/decrypt functions"""
    def __init__(self):
        self.PLAIN_FILE_NAME = ".acct_file"
        self.ENC_FILE_NAME = ".acct_file.cpt"
    
    def encrypt_file(self, sha256_key, plaintext=""):
        if not plaintext:
            try: 
                with open(self.PLAIN_FILE_NAME, encoding="utf8") as acct_file: 
                    plaintext = acct_file.read()
            except:
                exit(f"Could not open {self.PLAIN_FILE_NAME} file.")

        key = bytes.fromhex(sha256_key)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(bytearray(plaintext,'utf-8'), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        
        # WRITE file
        try:
            with open(self.ENC_FILE_NAME, "w") as f:
                f.write(result)
                print("writing: ",self.ENC_FILE_NAME)
        except:
            exit(f"Could not write {self.ENC_FILE_NAME} file.")
        print("Encryption complete")    
        return True
        
    def decrypt_file(self, sha256_key):
        try: 
            with open(self.ENC_FILE_NAME, encoding="utf8") as acct_file: 
                enc_input = acct_file.read()
        except:
            #exit(f"Could not open {self.ENC_FILE_NAME} file.")
            print("Nothing to decrypt")
            return False
        
        key = bytes.fromhex(sha256_key)
        b64 = json.loads(enc_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC,iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return( pt )            

class PwdUtil:
    """PwdUtil Class handles the master password function"""
    def __init__(self):
        self.PWD_FILE_DIR = "./"
        self.PWD_FILE = self.PWD_FILE_DIR + ".pmgr"
        self.SALT_SIZE = 16
        self.HASH_ITERATIONS = 5000000
        self.PWD_MIN_LEN = 10
    
    def add_user(self, uname, p_pwd):
        if not uname:
            return False
        if not self.password_strength(p_pwd):
            return False
        if not os.path.exists(self.PWD_FILE):
            file_mode = "w"
        else:
            file_mode = "a"
            if self.user_exists(uname):
                print(f"User {uname} already exists")
                return False
        try:
           with open(self.PWD_FILE,file_mode,newline='') as csvfile:
               writer = csv.writer(csvfile)
               salt = self.generate_salt()
               hash = self.generate_hash(p_pwd,salt)
               str_salt = str(salt).lstrip('b')
               str_salt = str_salt.rstrip("'")
               str_salt = str_salt.lstrip("'")
               writer.writerow([uname,str_salt,hash,datetime.date.today()])
        except:
            exit("Unable to open file add_user")

        
    def user_exists(self, uname):
        retval = False
        if not uname:
            return retval

        with open(self.PWD_FILE, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if uname.casefold() == row[0].casefold():
                    retval = True
        return retval
    
    
    def delete_user(self, uname, pwd):
        # WHOA!!! NEED TO USE THE PASSWORD OTHERWISE YOU CAN DELETE AN ACCOUNT WITHOUT VALIDATING
        print("See warning!")
        outfile = ""
        try:
            with open(self.PWD_FILE, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0].casefold() != uname.casefold():
                        outfile += row[0] + "," + row[1] + "," + row[2] + "," + row[3] + "\n"
        except:
            exit("Unable to delete user")
        try:    
            with open(self.PWD_FILE,'w',newline='') as f:
                f.write(outfile)
        except:        
            exit("Unable to delete user")
        return True

    def verify_user(self, uname,pwd):
        try:
            with open(self.PWD_FILE, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if uname.casefold() == row[0].casefold():
                        salt = row[1].encode('utf-8')
                        hashed = row[2]
                        pwd = pwd.encode('utf-8')
                        dk = pbkdf2_hmac('sha256', pwd, salt, self.HASH_ITERATIONS)                   
                        return (dk.hex() == hashed)
        except:
            exit("Unable to open password file.")
                    
        
    def generate_salt(self):
        return secrets.token_hex(self.SALT_SIZE).encode('utf-8')
        
    def generate_hash(self, pwd, salt):
        b_pwd = pwd.encode('utf-8')
        dk = pbkdf2_hmac('sha256', b_pwd, salt, self.HASH_ITERATIONS)
        return dk.hex()
        
    def password_strength(self, pwd):
        if len(pwd) < self.PWD_MIN_LEN:
            return False
        else:
            if re.search(r"[A-Z]", pwd) and re.search(r"[a-z]", pwd) and re.search(r"\d", pwd) and re.search(r"[@$!%*?&]", pwd):
                return True
        print(f"Password must have a minimum length of {self.PWD_MIN_LEN} characters and contain at least one uppercase character, one lowercase character, one number, and one special character (@ $ ! % * ? &)")
        return False

    def dictionary_check(self):
        pass
        # this will be for dictionary attacks.
        
    def password_age(self):
        pass #after 3 months a password is expired.
        #this involves marking previous passwords as expired and not actually deleting them
