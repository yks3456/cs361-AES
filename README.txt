UTEID: ksy228;
FIRSTNAME: Kyung;
LASTNAME: Yoo;
CSACCOUNT: ksy228;
EMAIL: ks-_-yoo92@hotmail.com;

[Program 4]
[Description]
There is only one file: AES.java. The encrypt() method calls the addRoundKey(), subBytes(), shiftRows(), and mixColumns() methods, and decrypt() method calls addRoundKey(), invSubBytes(), invShiftRows(), invMixColumns() methods in order specified by AES standards. The main method first reads the key file, stores it into an array, then processes it with expandKey() method to create an extended key. Then, it reads from the input file line from line, and calls encrypt() or decrypt() methods according to the command line arguments. To compile this program, you need to use "javac *.java" and to run this program, you need to use "java AES e key inputFile" for encryption, and "java AES d key inputFile" for decryption.

[Finish]
I finished all the requirements for this assignment.

[Test Cases]
[Input of Test 1]
plaintext

[Output of Test 1]
plaintext.enc
plaintext.enc.dec
Size: 32 MB
Encryption Throughput: 1.0834969 MB/s
Decryption Throughput: 1.0247871 MB/s

[Input of Test 2]
plaintext2

[Output of Test 2]
plaintext2.enc
plaintext2.enc.dec
Size: 1 MB
Encryption Throughput: 0.7541478 MB/s
Decryption Throughput: 0.7788162 MB/s