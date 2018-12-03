import os
from os import walk
import fileEncrypt as fEnc
import macEncrypt as macEnc
import rsaEncrypt as rsaEnc
import ransomPayload as ranPay
import ransomVaccination as ranVac

from os import listdir
from os.path import isfile,isdir,join

LengthOfKey = 32

def printMenu():
    print("Lab Main Menu")
    print(" 1) Encrypt/Decrypt Message")
    print(" 2) Encrypt/Decrypt Message (HMAC)")
    print(" 3) Encrypt/Decrypt File")
    print(" 4) Encrypt/Decrypt File (HMAC)")
    print(" 5) RSA Encryption")
    print(" 6) Ransomware")
    print(" 7) Exit Program")

def createFile(file, rootPath, text):
        #create new encrypted file name
        newDir = rootPath + file

        newFile = open(newDir, 'wb')
        newFile.write(text)
        newFile.close()

def main():
    program = True;
    while program:
        printMenu();
        menuInput = int(input("Enter input: "))
        if menuInput == 1:
            key = os.urandom(LengthOfKey)

            #Encrypting Message
            C, IV = fEnc.MyEncrypt(b"a secret message", key)
            print(b"Ciphertext: " + C)
            print()

            #Decrypting Message
            P = fEnc.MyDecrypt(C, key, IV)
            print(b"Plaintext: " + P)
            print()

        elif menuInput == 2:
            #Generating Keys for HMAC Encryption and Decryption
            EncKey = os.urandom(LengthOfKey)
            HMACKey = os.urandom(LengthOfKey)

            #Encrypting using HMAC
            C, IV, tagByte = macEnc.MyEncryptMAC(b"a secret message", EncKey, HMACKey)
            print(b"HMAC Ciphertext: " + C)
            print()

            #Decrypting using HMAC
            P = macEnc.MyDecryptMAC(C, EncKey, HMACKey, IV, tagByte)
            print(b"HMAC Plaintext: " + P)
            print()

        elif menuInput == 3:
            outputPath = "/home/airrick_/Documents/cybersecurity/Outputs/Encrypt-Decrypt/"
            #Encrypting File using HMAC
            file = "image.jpg"
            rootPath = "/home/airrick_/Documents/cybersecurity/File-Encryption/"
            filepath = rootPath + file
            C, IV, key, extension = fEnc.MyFileEncrypt(filepath)
            #Creating the encrypted file
            createFile("encryptedFile" + extension, outputPath, C)
            print("~File has been encrypted.")
            print()
            input("Press Enter to decrypt the file")
            #Decrypting File using HMAC
            encryptFilePath = outputPath + "encryptedFile" + extension
            P = fEnc.MyFileDecrypt(encryptFilePath, IV, key, extension)
            #Creating the decrypted file
            createFile("decryptedFile" + extension, outputPath, P)
            print("~File has been decrypted")
            print()

        elif menuInput == 4:
            outputPath = "/home/airrick_/Documents/cybersecurity/Outputs/Encrypt-Decrypt-HMAC/"
            #Encrypting File using HMAC
            file = "image.jpg"
            rootPath = "/home/airrick_/Documents/cybersecurity/File-Encryption/"
            filepath = rootPath + file
            C, IV, EncKey, HMACKey, extension, tagByte = macEnc.MyFileEncryptMAC(filepath)
            createFile("encryptedFile" + extension, outputPath, C)
            print("~File has been encrypted.")
            print()
            input("Press Enter to decrypt the file")
            #Decrypting File using HMAC
            encryptFilePath = outputPath + "encryptedFile" + extension
            P = macEnc.MyFileDecryptMAC(encryptFilePath, IV, EncKey, HMACKey, extension, tagByte)
            createFile("decryptedFile" + extension, outputPath, P)
            print("~File has been decrypted")
            print()

        elif menuInput == 5:
            outputPath = "/home/airrick_/Documents/cybersecurity/Outputs/RSA-Encryption/"
            #Test if there's public & private key; if not, then create them.
            #Store path into variables.
            publicKeyPath = "/home/airrick_/Documents/cybersecurity/Definitely-Not-Keys/publicKey.pem"
            privateKeyPath = "/home/airrick_/Documents/cybersecurity/Definitely-Not-Keys/privateKey.pem"
            filepath = "/home/airrick_/Documents/cybersecurity/File-Encryption/image.jpg"
            publicKey, privateKey = rsaEnc.writeKeys(publicKeyPath, privateKeyPath)
            RSACipher, C, IV, tagByte, extension = rsaEnc.MyRSAEncrypt(filepath, publicKey)
            createFile("encryptedFile" + extension, outputPath, C)
            print("~File has been encrypted.")
            print()
            input("Press Enter to decrypt the file")
            #Decrypting File using RSA
            encryptFilePath = outputPath + "encryptedFile" + extension
            P = rsaEnc.MyRSADecrypt(RSACipher, encryptFilePath, IV, tagByte, extension, privateKey)
            createFile("decryptedFile" + extension, outputPath, P)
            print("~File has been decrypted")
            print()

        elif menuInput == 6:
            #test encrypting and decrypting JSON 
            print("Encrypting to JSON")
            ranPay.payload()

            input("Press enter to encrypt")
            ranVac.vaccination()
           
        elif menuInput == 7:
            print("Exitting Program...")
            program = False;

        else:
            print("Invalid Input. Try Again.")

    print("Have a nice day!")
    print()
    input('press Enter to Exit')
main()
