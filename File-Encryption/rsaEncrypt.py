import fileEncrypt as fEnc
import macEncrypt as macEnc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64


primeNum = 65537
privateKeySize = 2049

def generateKeys():
    #Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent = primeNum,
        key_size = privateKeySize,
        backend = default_backend()
    )
    #public key generation
    public_key = private_key.public_key()
    return private_key, public_key

def writeKeys( RSA_Publickey_filepath, RSA_Privatekey_filepath ):
    my_file = Path(RSA_Publickey_filepath)
    my_file2 = Path(RSA_Privatekey_filepath)
    if my_file.is_file() & my_file2.is_file():
        print("The private and public key already exist")
    else:
        print("Writing private and public keys to folder...")
        private_key, public_key = generateKeys()
        #serialize private key
        private_pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        )

        #serialize public key
        public_pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        #public_pem.splitlines()[0]

        #write public key to pem file
        file = open(RSA_Publickey_filepath,'wb')
        file.write(public_pem)
        file.close()

        #write private key to pem file
        file = open(RSA_Privatekey_filepath,'wb')
        file.write(private_pem)
        file.close()
    return RSA_Publickey_filepath, RSA_Privatekey_filepath

def MyRSAEncrypt(filePath, RSA_Publickey_filepath):
    ct, iv, EncKey, HMACKey, extension, tagByte = macEnc.MyFileEncryptMAC(filePath)

    publicKeyData = open(RSA_Publickey_filepath,"rb").read()
    k = serialization.load_pem_public_key(publicKeyData, backend=default_backend())
    RSACipher = k.encrypt(EncKey+HMACKey,asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return RSACipher, ct, iv, tagByte, extension

def MyRSADecrypt(RSACipher, ct, IV, tagByte, ext, RSA_Privatekey_filepath):
    #load private key
    keyData = open(RSA_Privatekey_filepath,"rb").read()
    k = serialization.load_pem_private_key(keyData,password=None,backend=default_backend())
    #use private key to decrypt RSACipher
    d = k.decrypt(RSACipher, asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    EncKey = d[:32]
    HMACKey = d[-32:]

    pt = macEnc.MyFileDecryptMAC(ct, IV, EncKey, HMACKey, ext, tagByte)

    return pt
