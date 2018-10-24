import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
import base64

numByte = 16
numBit = 128
LengthOfKey = 32

def MyEncrypt(m, k):

    #encode to 64 bytes
    m = base64.b64encode(m)
    iv = os.urandom(numByte)

    #pad message, intiialize padder to pad ciphertext
    padder = padding.PKCS7(numBit).padder()
    padded_data = padder.update(m)
    padded_data += padder.finalize()
   
    #test if length of key is less than 32
    if len(k) < LengthOfKey:
        raise ValueError("Length of key has to be less than 32")
        return

    cipher = Cipher(algorithms.AES(k),modes.CBC(iv),backend=default_backend())
    encryptor = cipher.encryptor()
    result = encryptor.update(padded_data) + encryptor.finalize()

    #return ciphertext and iv
    return result, iv




#Function to decrypt a message
def MyDecrypt(ct, key, iv):

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    #remove the pad from the plaintext
    unpadder = padding.PKCS7(numBit).unpadder()
    result = unpadder.update(pt) + unpadder.finalize()
    result = base64.b64decode(result)
    #return plaintext
    return result




def MyFileEncrypt(filepath):

    #Splits the file name text using periods
    #Stores them into an array (extention is in the last index)
    extension=os.path.splitext(filepath)[-1]
        
    #generate a 32Byte Key
    key = os.urandom(32)

    #open
    file = open(filepath, 'rb')
    readFile = file.read()
    file.close()
        
    #Call MyEncrypt to encrypt the filetext
    ct, iv = MyEncrypt(readFile,key)

    #create new encrypted file name
    newDir = "/home/airrick_/Documents/cybersecurity/encryptedFile"+extension       

    #make new encrypted file
    #read file in binary
    newFile = open(newDir, 'wb')
    #write new ciphertext into the file
    newFile.write(ctFile)
    newFile.close()
    
    print("~File has been encrypted~")
    #return cipher C, IV, key, and extension of the file(as string)
    return ctFile, iv, key, extension
       



 
def MyFileDecrypt(ctFile, iv, key, extension):

    #Decrypted File destination
    save = "/home/airrick_/Documents/cybersecurity/decryptedFile" + extension

    #Read the contents of the file in bytes, then decrypt it.
    myFile = open(ctFile, 'rb')
    fileContent = myFile.read()
    data = MyDecrypt(fileContent, key, iv)

    #Write the decrypted contents back into a new file.
    newFile = open(save, 'wb')
    newFile.write(data)
    newFile.close()
    print("~File has been decrypted~")
    return data





#Function to encrypt the message then generate the tag
def MyEncryptMAC(m, EncKey, HMACKey):

    ct, iv = MyEncrypt(m, EncKey)
    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag.update(ct)
    #return ciphertext, IV, and digest (in bytes)
    return ct, iv, tag.finalize()





#Function to decrypt a message if the tag is verified
def MyDecryptMAC(ct, EncKey, HMACKey, iv, tag):

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    h.verify(tag)
    pt = MyDecrypt(ct, EncKey, iv)
    return pt



def MyFileEncryptMAC(filepath):

    #Splits the file name text using periods
    #Stores them into an array (extention is in the last index)
    extension = os.path.splitext(filepath)[-1]
        
    #generate a Encryption Key and HMAC Key of specified length
    EncKey = os.urandom(LengthOfKey)
    HMACKey = os.urandom(LengthOfKey)

    #open
    file = open(filepath, 'rb')
    readFile = file.read()
    file.close()
        
    #Call MyEncryptMAC to encrypt the filetext using HMAC
    ct, iv, tagByte = MyEncryptMAC(readFile, EncKey, HMACKey)

    #create new encrypted file name
    newDir = "/home/airrick_/Documents/cybersecurity/File-Encryption/encryptedFile"+extension       

    #make new encrypted file
    #read file in binary
    newFile = open(newDir, 'wb')
    #write new ciphertext into the file
    newFile.write(ct)
    newFile.close()
    
    print("~File has been encrypted~")
    #return cipher C, IV, key, and extension of the file(as string)
    return ct, iv, EncKey, HMACKey, extension, tagByte




def MyFileDecryptMAC(ctFile, iv, EncKey, HMACKey, extension, tag):

    save = "/home/airrick_/Documents/cybersecurity/File-Encryption/decryptedFile" + extension

    myFile = open(ctFile, 'rb')
    fileContent = myFile.read()
    data = MyDecryptMAC(fileContent, EncKey, HMACKey, iv, tag) #HMAC Decryption

    newFile = open(save, 'wb')
    newFile.write(data)
    newFile.close()
    print("~File has been decrypted~")
    return data




def main():
    key = os.urandom(LengthOfKey)
    
    #Encrypting Message
    C, IV = MyEncrypt(b"a secret message", key)
    print(b"Ciphertext: " + C)
    print()

    #Decrypting Message
    P = MyDecrypt(C, key, IV)
    print(b"Plaintext: " + P)
    print()

    #Generating Keys for HMAC Encryption and Decryption
    EncKey = os.urandom(LengthOfKey)
    HMACKey = os.urandom(LengthOfKey)

    #Encrypting using HMAC
    C2, IV2, tagByte = MyEncryptMAC(b"a secret message", EncKey, HMACKey)
    print(b"HMAC Ciphertext: " + C2)
    print()
    
    #Decrypting using HMAC
    P2 = MyDecryptMAC(C2, EncKey, HMACKey, IV2, tagByte)
    print(b"HMAC Plaintext: " + P2)
    print()
    
    #Encrypting File using HMAC
    filepath = "/home/airrick_/Documents/cybersecurity/File-Encryption/image.jpg"
    C3, IV3, EncKey2, HMACKey2, extension, tagByte2 = MyFileEncryptMAC(filepath)

    #Decrypting File using HMAC
    encryptFilePath = "/home/airrick_/Documents/cybersecurity/File-Encryption/encryptedFile" + extension
    pt = MyFileDecryptMAC(encryptFilePath, IV3, EncKey2, HMACKey2, extension, tagByte2)
    
main()
