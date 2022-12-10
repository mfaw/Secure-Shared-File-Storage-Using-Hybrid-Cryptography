import ftplib
import sys
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad
import os


class Decryptor:
    def __init__(self) -> None:
        self.masterKey = None
        self.decrypt = []
        self.masterCipherBlockSize = 16
    def parseMasterKey(self, filename):
        with open(filename , 'r') as outfile:
            data = json.load(outfile)
        self.masterKey = b64decode(data['key'])
        self.masterType = data['type']
        if(self.masterType == AES):
            self.masterCipher = AES.new(self.masterKey , AES.MODE_ECB)
        else:
            self.masterCipher = AES.new(self.masterKey , AES.MODE_ECB)
       

    def parseKeys(self , filename):
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
            self.decrypt[obj['index']] = singleObj
        print(self.decrypt)
    def decryptFile(self,filename): 
        i = 0
        with open(filename , 'rb') as inFile :
            with open("result.txt", 'w') as outFile:
                while True:
                    cipherObject = self.decrypt[i%len(self.decrypt)]
                    i+=1
                    block = inFile.read(cipherObject['size'])
                    if(len(block) == 0):
                        break
                    ct = cipherObject['cipher'].decrypt(block)
                    ct = ct.decode('utf-8')
                    outFile.write(ct)




x = Decryptor()
