import sys

from Crypto import Random
from Crypto.Cipher import AES

#Strings have to be decoded if the string is in hex
def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def padd(IV,msg):
    #Number of bytes
    mess_length=len(msg)/2    
    IV_len=len(IV.encode('hex'))/2
    extra_bytes=mess_length%IV_len
    padd_bytes=IV_len-extra_bytes
        
    for x in range(0,padd_bytes):
        msg+="{:02x}".format(padd_bytes)

    return msg

def cbc_de(key,previous, next):
    aes = AES.new(key)
    #temp = aes.decrypt(next).encode('hex')
    
    return strxor(previous.decode('hex'),aes.decrypt(next))

def cbc_decryption():
    
    K = open('Encryption Key.txt','r')
    key=K.read().decode('hex')

    I = open('IV.txt','r')
    IV=I.read().decode('hex')

    O = open('Encrypted Text.txt','r')  
    ct=O.read()

    length = len(ct)
    num_mess = length/len(key.encode('hex'))
    
    temp=""
    for x in range(0,num_mess):
        temp+=cbc_de(key,ct[x*32:(x+1)*32],ct[(x+1)*32:(x+2)*32])

    print "Decrypted\t"+temp.encode('hex')
    print "Encrypted\t"+ct
    return temp

def main():
    D = open('Decrypted Text.txt','w')
    D.write(cbc_decryption())
    
if __name__ == "__main__":
    main()
