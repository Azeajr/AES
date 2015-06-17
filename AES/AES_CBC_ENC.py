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

def cbc(key,previous, next):
    #temp = strxor(previous.decode('hex'),next.decode('hex'))
    aes = AES.new(key)
    return aes.encrypt(strxor(previous.decode('hex'),next.decode('hex'))).encode('hex')

def cbc_encryption():
    
    key = Random.new().read(16)
    K = open('Encryption Key.txt','w')
    K.write(key.encode('hex'))

    IV = Random.new().read(16)
    I = open('IV.txt','w')
    I.write(IV.encode('hex'))

    #MSGS = []
    #ENC_MSGS=[]
    M = open('Message.txt', 'r')
    msg=IV.encode('hex') + M.read().encode('hex')
    
    prepared=padd(IV,msg)
    print prepared
    length = len(msg)
    num_mess = length/len(key.encode('hex'))
 
    temp=msg[0:32]
    for x in range(0,num_mess+1):
        temp+=cbc(key,temp[x*32:(x+1)*32],msg[x*32:(x+1)*32])

    print str(len(temp)/len(key.encode('hex')))
    print str(len(msg)/len(key.encode('hex')))
    
    return temp



def main():
    O = open('Encrypted Text.txt','w')  
    O.write(cbc_encryption())
    
if __name__ == "__main__":
    main()
