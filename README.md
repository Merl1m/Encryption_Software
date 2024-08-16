# Encryption Software
Simple script to encrypt and decrypt a file or directory. This isn't like a bitlocker type encryption but rather the script takes in a *Path*, option of *Encryption* or *Decryption* and a *Password* to do the Encryption or Decryption as specified.

The Encryption is done on files by replacing the data within files to the encrypted form of the data, the encryption of data is done using a module named _cryptography_ using a key made from password that is input.

The key is made by using a password of length less than or equal to 32 characters. The password is converted to 32 characters by adding "0", for example if the password input was *'mycat123'* which is 8 characters, it is converted to *'mycat123000000000000000000000000'*. Then the password is encoded in base64 and is used as the key for encryption or decryption.

Encrypted files will have a new extension *'.encrypted'* along with the orginal extension, for example if the file before encryption is named _'secret.txt'_, the new encrypted file would be _'secret.txt.encrypted'_

# Module Installation
Use command prompt or terminal; type `pip3 install -r requirements.txt` to install the required modules.

Once the Module _cryptography_ is installed, you are good to run the script. Also a last bit information, the script is coded and tested in python 3 and windows environment.

