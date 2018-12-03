import os
import fileEncrypt as fEnc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

LengthOfKey = 32

#Function to encrypt the message then generate the tag using ciphertext
def MyEncryptMAC(m, EncKey, HMACKey):
    ct, iv = fEnc.MyEncrypt(m, EncKey)
    #generate a tag using Hash-Based Message Authentication codes
    #this calculates message authentication codes using cryptographic hash function with a secret key
    #this is to verify integrity and authenticity of a message
    #setup HMAC after we encrypt
    #HMAC: H( Ko || H (Ki||m))
    #MAC: message authentication code is known as the tag, a short piece of info to authenticate msg
    #HMAC is used to verify or authenticate that data has not been altered or replaced

    #generate the tag
    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())

    #update ciphertext for tag
    #hash the ciphertext
    tag.update(ct)
    #return ciphertext, IV, and tag (in bytes) where the HMAC is finalized
    #after finalize is called tag can no longer be used
    #encrypt first then mac, then put them together
    return ct, iv, tag.finalize()

#Function to decrypt a message if the tag is verified
def MyDecryptMAC(ct, EncKey, HMACKey, iv, tag):
    #SHA256 is a cryptographic hash algorithm
    #crytographic hash aka digest is used as a kind of a signature for text or data file
    #SHA256 is good enough
    #generate another hmac to verify that info/data wasn't modified
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    #update ciphertext for HMAC
    #hash the ciphertext
    h.update(ct)
    #finalize the current context and securely compare digest to signature
    h.verify(tag)
    pt = fEnc.MyDecrypt(ct, EncKey, iv)
    return pt

def MyFileEncryptMAC(filePath):
    #generate extension encryption for file
    #to split extension by the period of the filepath name
    #splitting into two arrays, [0] and [1] and [1] is the txt that gets called as extension
    extension = os.path.splitext(filePath)[-1]

    #generate a Encryption Key and HMAC Key of specified length every single time function is called
    EncKey = os.urandom(LengthOfKey)
    HMACKey = os.urandom(LengthOfKey)

    #open
    myFile = open(filePath, 'rb')
    readFile = myFile.read()
    myFile.close()

    #call above method to encrypt file using key generated
    ct, iv, tagByte = MyEncryptMAC(readFile, EncKey, HMACKey) #HMAC Encryption

    #return cipher C, IV, key, and extension of the file(as string)
    return ct, iv, EncKey, HMACKey, extension, tagByte

def MyFileDecryptMAC(ct, iv, EncKey, HMACKey, extension, tag):
    '''
    myFile = open(ctFile, 'rb')
    ct = myFile.read()
    myFile.close()
    '''
    pt = MyDecryptMAC(ct, EncKey, HMACKey, iv, tag) #HMAC Decryption

    return pt
