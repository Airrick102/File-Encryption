import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from pathlib import Path

numByte = 16
numBit = 128
LengthOfKey = 32

def MyEncrypt(m, k):
    #encode to 64 bytes
    m = base64.b64encode(m)
    iv = os.urandom(numByte)

    #pad message, intiialize padder to pad ciphertext
    padder = padding.PKCS7(numBit).padder()
    #update m into the padded data, only takes first block of 16 bytes
    #pick 128 for now so you can encrypt and decrypt evenly, left and right has to be equal
    padded_data = padder.update(m)
    #before finalize it would not match
    #finalize current context and return remainder of message to fill up 128 bits
    #takes the leftover of 128 bits to make it total
    #after finalize is called object can no longer be used
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
    extension = os.path.splitext(filepath)[-1]

    #generate a 32Byte Key
    key = os.urandom(LengthOfKey)

    #open
    file = open(filepath, 'rb')
    readFile = file.read()
    file.close()

    #call above moethod to encrypt file using key generated
    ct, iv = MyEncrypt(readFile,key)

    #return cipher C, IV, key, and extension of the file(as string)
    return ct, iv, key, extension

def MyFileDecrypt(ctFile, iv, key, extension):
    #Read the contents of the file in bytes, then decrypt it..
    myFile = open(ctFile, 'rb')
    fileContent = myFile.read()
    myFile.close()

    pt = MyDecrypt(fileContent, key, iv)

    return pt
