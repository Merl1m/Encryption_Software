# Encryption Software
Simple script to encrypt and decrypt a file or directory. This isn't like a bitlocker type encryption but rather the script takes in a *Path*, option of *Encryption* or *Decryption* and a *Password* to do the Encryption or Decryption as specified.

The Encryption is done on files by replacing the data within files to the encrypted form of the data, the encryption of data is done using a module named _cryptography_ using a key made from password that is input. 

The key is made by using a password which is hashed in sha256 algorithm and half of hash string is taken and converted to base64. This base64 string is the key.

Encrypted files will have a new extension *'.encrypted'* along with the orginal extension, for example if the file before encryption is named _'secret.txt'_, the new encrypted file would be _'secret.txt.encrypted'_

Encryption can be done a particular file type by providing file extensions when prompted, and all the files with extensions given in the prompt would be encrypted.

# Module Installation
Use command prompt or terminal; type `pip3 install -r requirements.txt` to install the required modules.

Once the Module _cryptography_ is installed, you are good to run the script. Also a last bit information, the script is coded and tested in python 3 and windows environment.

