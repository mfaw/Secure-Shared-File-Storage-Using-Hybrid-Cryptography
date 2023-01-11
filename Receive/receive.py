import ftplib
import sys
from Crypto.Cipher import AES, DES , ARC2 , Blowfish
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import requests
import json
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad
import os
from Crypto.PublicKey import RSA

import hashlib
class Decryptor:
    def __init__(self) -> None:
        self.masterKey = None
        self.decrypt = []
        self.masterCipherBlockSize = 16
    def parseMasterKey(self, filename , decrptFile):
        with open(filename , 'r') as outfile:
            data = json.load(outfile)
        self.masterKey = b64decode(data[decrptFile])
        self.masterCipher = Blowfish.new(self.masterKey , Blowfish.MODE_ECB)
       

    def parseKeys(self , filename):
        filename = f"files/{fileName}.key.enc"
        with open(filename , 'rb') as inFile:
            with open("keys.json" , 'w') as outFile:
                while True:
                    block = inFile.read(self.masterCipherBlockSize)
                    if(len(block) == 0):
                        break
                    ct = self.masterCipher.decrypt(block)
                    ct = ct.decode('utf-8')
                    outFile.write(ct)
        inFile.close()
        outFile.close()
        self.keys = None
        with open('keys.json' , 'r') as outfile:
                self.keys = json.load(outfile)
        

    def createDeciphers(self):
        self.decrypt = [None for i in range(len(self.keys))]
        for obj in self.keys:
            key = b64decode(obj['key'])
            if(obj['type'] == "AES"):
                singleObj = {
                        'size' : AES.block_size,
                        'type' : 'AES',
                        'cipher' : AES.new(key , AES.MODE_ECB)
                    }
            elif(obj['type'] == "DES"):
                singleObj = {
                        'size' : DES.block_size,
                        'type' : 'DES',
                        'cipher' : DES.new(key , AES.MODE_ECB)
                    }
            elif(obj['type'] == "ARC2"):
                 singleObj = {
                            'size' : ARC2.block_size,
                            'type' : 'ARC2',
                            'cipher' : ARC2.new(key, ARC2.MODE_ECB)
                    }
            self.decrypt[obj['index']] = singleObj
        print(self.decrypt)
    def decryptFile(self,filename): 
        filenameToRead = f"files/{fileName}.enc"
        i = 0
        with open(filenameToRead , 'rb') as inFile :
            with open(f"results/{filename}.txt", 'w') as outFile:
                while True:
                    cipherObject = self.decrypt[i%len(self.decrypt)]
                    i+=1
                    block = inFile.read(cipherObject['size'])
                    if(len(block) == 0):
                        break
                    ct = cipherObject['cipher'].decrypt(block)
                    ct = ct.decode('utf-8')
                    outFile.write(ct)
        inFile.close()
        outFile.close()


x = Decryptor()


keyPair = RSA.generate(3072)
pubKey = keyPair.publickey()

pubKeyPEM = hex(pubKey.n)
print(pubKeyPEM)
print(type(pubKeyPEM))

a = pubKeyPEM.encode('utf-8')


while True:
    choice = int(input("1- list all of the available files in the FTP sever\n2- to retrive a file \n3- list of the files that you can decrypt\n4- to decrypt a file\n5- recive all master keys requested\n6- close the terminal\n\n> "))
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
    print("\n")
    if(choice == 1):   
        files_in_FTP = ftp.nlst()
        mySet = set()
        for file in files_in_FTP:
            mySet.add(file.split('.')[0])
        
        for i in mySet:
            print(i)

    elif(choice == 2):
        fileName = str(input("please input the filename you want to retrive: "))
        files_in_FTP = ftp.nlst()
        for file in files_in_FTP:
            if(fileName+'.' in file):
                with open(f"files\{file}", 'wb') as fp:
                    ftp.retrbinary(f'RETR {file}', fp.write)

        response = requests.post('http://192.168.1.11:5000/requestfile' , json={ "key" : {'n' : pubKey.n , 'e' : pubKey.e} , "filename" : fileName})

        if(response.status_code == 200):
            print("master key request sent!")

        

    elif(choice == 3):
        data = {}
        if(os.path.isfile('fileToMasterkey.json')):
            with open('fileToMasterkey.json' , 'r') as outfile:
                data = json.load(outfile)
            for key in data:
                print(key)
        else:
            print("no files found to decrypt")

    
    elif(choice == 4):
        fileName = str(input("please input the filename you want to decrypt: "))
        x.parseMasterKey('fileToMasterkey.json' , fileName)
        x.parseKeys(fileName)
        x.createDeciphers()
        x.decryptFile(fileName)
    elif(choice == 5):
        response = requests.post('http://192.168.1.11:5000/checkMasterKeys' , json={'n' : str(pubKey.n)})


        if(response.status_code == 200):
            payloads = response.json()
            for payload in payloads:
                data = {}
                decryptor = PKCS1_OAEP.new(keyPair)
                masterKey = decryptor.decrypt(b64decode(payload['masterKey']))
                masterKey = b64encode(masterKey).decode('utf-8')

                if(os.path.isfile('fileToMasterkey.json')):
                    with open('fileToMasterkey.json' , 'r') as outfile:
                        data = json.load(outfile)

                data[payload['filename']]  = masterKey
                with open('fileToMasterkey.json' , 'w+') as write_file:
                    json.dump(data, write_file, indent=4)
    elif(choice == 6):
        ftp.quit()
        break
    ftp.quit()
    print("\n")

