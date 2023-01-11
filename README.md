# Secure-Shared-File-Storage-Using-Hybrid-Cryptography

Objective: To Achieve a secure shared file access using Hybrid Cryptography and FTP FTP is an old Internet protocol where files can be shared via upload/download mechanism. The purpose of this project is to build a secure platform of file sharing using FTP and multiple ciphers encryption. The requirements are that a file owner can upload an encrypted file to an FTP server. Other users can download the file from the server and then request the encryption keys of the file using their public keys, hence only the users granted this key can decrypt the downloaded file

File Storage (sender perspective):

1.	Dividing the file to upload into N parts. (N depends on the file size, as well as the current cipher used in the round robin iteration)
2.	Generate m keys randomly, where m is the number of symmetric ciphers used (at least 3 ciphers including DES and AES, and you may choose a third one or even your own cipher)
3.	Encrypting all the parts of the file using one of the selected algorithms (Algorithm is changed with every part in round robin fashion). And the parts are put together in a single file as ordered.
4.	The keys for cryptography algorithms are then grouped in a key file and encrypted using a different algorithm and the key for this algorithm is also generated randomly and is called the file master key.
5.	The data file and the key file are than uploaded to the FTP server
6.	A copy of the master key is kept in a local file with the file name to be shared

This all will be exposed as simple GUI interface to the clint to be able to use it

File Retrieval (receiver perspective):
1.	A user requesting the master key must provide his public key to the owner
2.	The owner then encrypts the master key of the requested file with the requesting user public key and sends it to him
3.	The user can then download the data file and the key file, decrypts the master key with his private key and then decrypts the data file
The exchanging of the public key is done through a simple Client-server backend where the receiver submit the request for a specific file master key, and the backend server will cache this request for the sender to receive and process the master key and encrypt it using the receiver public key and then will submit the encrypted master key back to the backend server for the receiver to be able to receive it and decrypt it using his own private key.

