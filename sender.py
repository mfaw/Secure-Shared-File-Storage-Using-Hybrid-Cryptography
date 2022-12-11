import ftplib
import sys
from Crypto.Cipher import AES, DES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad
import os
import requests
from Crypto.PublicKey import RSA
import hashlib

keyAES = get_random_bytes(16)
keyDES = get_random_bytes(8)
cipherAES = AES.new(keyAES, AES.MODE_CBC)
cipherDES = DES.new(keyDES, AES.MODE_CBC)
class Encryptor:
    def __init__ (self, cyphers = ['AES' , 'DES'], masterCipherType = 'AES'):
        self.dataFile = None
        self.keyFile = None
        self.keys = []
        self.cyphers = []
        self.masterKey = None
        self.initialize(cyphers=cyphers)
        self.masterCipherType = masterCipherType
        self.masterCipher = None

    def initialize(self, cyphers):
        self.cyphers = []
        self.keys = []
        self.masterKey = None
        i = -1
        for c in cyphers:
            i+=1
            if(c == 'AES'):
                key = get_random_bytes(16)
                self.keys.append({
                    'type' : 'AES',
                    'key' : b64encode(key).decode('utf-8'),
                    'index' : i
                })
                self.cyphers.append({
                    'size' : AES.block_size,
                    'type' : 'AES',
                    'cipher' : AES.new(key , AES.MODE_ECB)
                })
            elif (c == 'DES'):
                key = get_random_bytes(8)
                self.keys.append({
                    'type' : 'DES',
                    'key' : b64encode(key).decode('utf-8'),
                    'index' : i
                })
                self.cyphers.append({
                    'size' : DES.block_size,
                    'type' : 'DES',
                    'cipher' : DES.new(key, DES.MODE_ECB)
                })
    
    def encryptFile(self , file , outfile = None , reinitialize = True ,cyphers = ['AES' , 'DES']):
        if(reinitialize):
            self.initialize(cyphers)
        if not outfile:
            outfile = file.split('/')[-1].split('.')[0]+ '.enc'

        self.inFile = file.split('/')[-1]   
        i = 0
        with open(file , 'rb') as inFile :
            with open(outfile, 'wb') as outFile:
                while True:
                    cipherObject = self.cyphers[i%len(self.cyphers)]
                    i+=1
                    block = inFile.read(cipherObject['size'])

                    if(len(block) == 0):
                        break
                    elif(len(block) % cipherObject['size'] != 0):
                         block += b' ' * (cipherObject['size'] - len(block)) 

                    ct = cipherObject['cipher'].encrypt(block)
                    outFile.write(ct)

        inFile.close()
        outFile.close()

        self.dataFile = outfile
        self.keyFile = self.dataFile.split('.')[0] +'.key' + '.json'
        self.keyFileEncrypted = self.dataFile.split('.')[0] +'.key'+'.enc' 
        self.initializeMasterCipher()
        self.saveKeyFile()
        self.encryptKeyFile()
        self.saveMasterKey()
        print("key file encrypted -> " , self.keyFileEncrypted)
        print("Data file encrypted ->" , self.dataFile)
        print("key file -> " , self.keyFile)
        print("Data file ->" , self.inFile)
        print("master key ->" , self.masterKey)
        

    def initializeMasterCipher(self):
        if(self.masterCipherType == 'AES'):
            self.masterKey = get_random_bytes(16)
            self.masterCipher = AES.new(self.masterKey , AES.MODE_ECB)
            self.masterCipherBlockSize = 16

    def saveMasterKey(self):
        data = {}
        if(os.path.isfile('fileToMasterkey.json')):
                
            with open('fileToMasterkey.json' , 'r') as outfile:
                data = json.load(outfile)
        if(data.get(self.inFile.split('.')[0]) == None):
            data[self.inFile.split('.')[0]] = {
                'key' : b64encode(self.masterKey).decode('utf-8'),
                'type':"AES"
            }
            with open('fileToMasterkey.json' , 'w+') as write_file:
                json.dump(data, write_file, indent=4)
        else:
            print("-"*20,"ERROR Change file name" , "-"*20)

    def encryptKeyFile(self):
        with open(self.keyFile , 'rb') as inFile :
            with open(self.keyFileEncrypted, 'wb') as outFile:
                while True:
                    cipherObject = self.masterCipher
                    block = inFile.read(self.masterCipherBlockSize)
                    if(len(block) == 0):
                        break
                    elif(len(block) % self.masterCipherBlockSize != 0):
                        block+= b' ' * (self.masterCipherBlockSize - len(block)) 

                    ct = cipherObject.encrypt(block)
                    outFile.write(ct)
        inFile.close()
        outFile.close()

    def saveKeyFile(self):
        with open(f"{self.keyFile}", "w") as write_file:
            json.dump(self.keys, write_file, indent=4)

    def sendFiles(self):
        # FTP server credentials
        FTP_HOST = "127.0.0.1"
        FTP_PORT = 6060
        FTP_USER = "username"
        FTP_PASS = "password"
        # connect to the FTP server
        ftp = ftplib.FTP()
        ftp.connect(FTP_HOST,FTP_PORT)
        ftp.login(FTP_USER,FTP_PASS)
        # force UTF-8 encoding
        ftp.encoding = "utf-8"
        # local file name you want to upload
        print(self.keyFileEncrypted)
        with open(self.keyFileEncrypted, "rb") as file:
        # use FTP's STOR command to upload the file
            ftp.storbinary(f"STOR {self.keyFileEncrypted}", file)
        with open(self.dataFile, "rb") as file:
        # use FTP's STOR command to upload the file
            ftp.storbinary(f"STOR {self.dataFile}", file)
        # quit and close the connection
        ftp.quit()  



x = Encryptor()


data = 'hello'
print("data -> " , data , type(data) , sys.getsizeof(data) , len(data))
data = data.encode('utf-8')
print("data.encode('utf-8') -> " , data , type(data) , sys.getsizeof(data) , len(data))
data = b64encode(data)
print("b64encode(data.encode('utf-8')) -> " , data , type(data) , sys.getsizeof(data) , len(data))
data.decode('utf-8')
print("b64encode(data.encode('utf-8')).decode('utf-8') -> " , data , type(data) , sys.getsizeof(data) , len(data))
data = b64decode(data)
print("b64decode(b64encode(data.encode('utf-8')).decode('utf-8')) -> " , data , type(data) , sys.getsizeof(data) , len(data))



while True:
    choice = int(input("1- list all files you can encrypt\n2- encrypt a file\n3- check all master keys requests and reply\n\n> "))
    if(choice == 1):
        dir_list = os.listdir("./")
        mySet = set()
        for file in dir_list:
            mySet.add(file.split('.')[0])
        
        for i in mySet:
            print(i)

    elif(choice == 2):
        # filename = str(input("input file name to encrypt: "))
        x.encryptFile("C:/my computer/textfile.txt")
        x.sendFiles()
        print("file sent")
    elif(choice == 3):
        response = requests.get("http://192.168.1.11:5000/checkMasterKeysRequests")
        if(response.status_code == 200):
            with open('fileToMasterkey.json' , 'r') as outfile:
                dataJson = json.load(outfile)
            
            payloads = response.json()
            for file in payloads:
                for payload in payloads[file]:
                    dataToEncrypt = str(dataJson[file]['key'])
                    dataToEncrypt.encode('utf-8')
                    dataToEncrypt = b64decode(dataToEncrypt)
                    RSAKEY = [payload['n'] , payload['e']]
                    pubKey = RSA.construct(tuple(RSAKEY))
                    encryptor = PKCS1_OAEP.new(pubKey)
                    encrypted = encryptor.encrypt(dataToEncrypt)
                    encrypted = b64encode(encrypted).decode('utf-8')
                    response = requests.post("http://192.168.1.11:5000/submitMasterKey" , json = {"message" : 
                    encrypted, "n" :  str(payload['n']),"file" : file})


    print("\n")










    # f.close()
    # key = get_random_bytes(16)
    # cipher = AES.new(key, AES.MODE_CBC)
    # ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    # iv = b64encode(cipher.iv).decode('utf-8')
    # ct = b64encode(ct_bytes).decode('utf-8')
    # result = json.loads(json.dumps({'iv':iv, 'ciphertext':ct}))
    # print(result)
    # print(os.path.getsize(file))

# data = "hello"
# print("data -> " , data , type(data) , sys.getsizeof(data) , len(data))
# data = data.encode('utf-8')
# print("data.encode('utf-8') -> " , data , type(data) , sys.getsizeof(data) , len(data))
# data = b64encode(data)
# print("b64encode(data.encode('utf-8')) -> " , data , type(data) , sys.getsizeof(data) , len(data))
# data.decode('utf-8')
# print("b64encode(data.encode('utf-8')).decode('utf-8') -> " , data , type(data) , sys.getsizeof(data) , len(data))
# data = b64decode(data)
# print("b64decode(b64encode(data.encode('utf-8')).decode('utf-8')) -> " , data , type(data) , sys.getsizeof(data) , len(data))




# try:
#     iv = b64decode(result["iv"])
#     ct = b64decode(result['ciphertext'])
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     pt = unpad(cipher.decrypt(ct), AES.block_size)
#     print("The message was: ", pt.decode('utf-8'))
# except (ValueError, KeyError):
#     print("Incorrect decryption")


# encrypt_AES_CBC('sometextfile.txt')

