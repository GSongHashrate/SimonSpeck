SimonSpeck
==========

Simon &amp; Speck block cipher implementation open source code in C

Implemented all vesion based on the test vectors in original NSA paper.

Including algrebric equation generation for Simon64/128 version, which can be used for algrebric attack using ElimLin or SAT solver. 

More details see:
http://www.cryptosystem.net/aes/toyciphers.html
and
http://www.cryptosystem.net/aes/tools.html


Simon.exe Nr /insX [/cp] [/fixkY]. Legend:
- Nr=number of rounds,
- /insX means use X plaintext/ciphertext pairs, for example X=2.
- /fixkY means fix Y key bits out of 128[currently] to their values to reduce the key space.
- with the option /cp the plaintexts are chosen to be consecutive - it is a counter mode in which different plaintexts differ very little, a sort of Chosen Plaintext Attack. 


