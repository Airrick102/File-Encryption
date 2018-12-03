
import os
from os import walk
import base64
import json
import rsaEncrypt as rsaEnc

def decryptJSON( jFile, rootPath,  privateKey ):
    #get json file name
    jFileName = os.path.splitext(jFile)[0]
    #concatenate root path and json file path
    jsonPath = rootPath + jFile

    with open(jsonPath,'r') as f:
        data = json.load(f)

    #load file contents into variables
    ct = base64.b64decode(data['ciphertext'])
    tag = base64.b64decode(data['tag'])
    iv = base64.b64decode(data['iv'])
    ext = data['file_ext']
    key = base64.b64decode(data['RSACipher'])

    #plaintext
    pt = rsaEnc.MyRSADecrypt(key, ct, iv, tag, ext, privateKey)

    #add the extension back
    outputFile = jFileName + ext

    #write back the file using plaintext
    f = open(rootPath + outputFile, 'wb')
    f.write(pt)
    f.close()

    filename = (rootPath + jFile)
    #remove remaining file if it is a json file
    if filename.endswith('.json'):
        os.remove(filename)
    return outputFile
def vaccination():
    outputPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Outputs\\Ransomware\\"
#Ransomware. Select root path.
    publicKeyPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Definitely-Not-Keys\\publicTransportation.pem"
    privateKeyPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Definitely-Not-Keys\\privateTransportation.pem"
    rootPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Outputs\\Ransomware\\"
    publicKey, privateKey = rsaEnc.writeKeys(publicKeyPath, privateKeyPath)
    for root, dirs, files in walk(rootPath):
        #absolute path
        root = (root +'\\')
        #for every file name in listed files
        for fName in files:
            #decrypt json files into output files
            outputFile = decryptJSON(fName, root, privateKey)
    print("decrypted...")
vaccination()
