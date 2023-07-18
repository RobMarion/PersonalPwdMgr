## Personal Password Manager  
I started writing this to be my own personal password manager after all the big ones were hacked. What I thought would be a very simple CLI-based project for storing my own passwords as simply as possible turned into a fun learning experience. This project is morphing into a multi-user application that I may host on AWS when complete.  
  
I do not recommend using this code to actually secure anything (yet). 

For now, there are a few files:  
PwdManager.py: This does all the work  
keyfinder.py:  This is a CLI menu bit of code that uses the PwdManager functionality.  
.pmgr: This stores user names, salt, hashed password and the date the password was updated/created.  It will be created if one does not exist.  
.acct_file.cpt: the encrypted account names, passwords, and dates they were updated/created.  

Symmetric encryption uses the Python library Crypto using a Sha256 key to AES 256 encrypt using CBC Mode.  

My go to for crypto concepts was: [Cryptography Engineering: Design Principles and Practical Applications](https://www.wiley.com/en-us/Cryptography+Engineering:+Design+Principles+and+Practical+Applications+-p-9780470474242) by Niels Ferguson, Bruce Schneier, Tadayoshi Kohno. The book is now over ten years old and so any developments in the last 10+ years will obviously be missing.