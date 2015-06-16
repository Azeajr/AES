import sys

from Crypto import Random
from Crypto.Cipher import AES


key = Random.new().read(16)
K = open('Encryption Key.txt','w')
K.write(key.encode('hex') + "\n")

IV = Random.new().read(16)
I = open('IV.txt','w')
I.write(IV.encode('hex') + "\n")

MSGS = []
ENC_MSGS=[]
M = open('Messages.txt', 'r')
    
for line in M:
    MSGS.append(IV.encode('hex') + line.rstrip('\n').encode('hex'))

#Strings have to be decoded if the string is in hex
def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def padd(msg):
    #Number of bytes
    print "Padding"
    mess_length=len(msg)/2
    print "Message length in bytes: " + str(mess_length)
    
    IV_len=len(IV.encode('hex'))/2
    print "IV length in bytes: " + str(IV_len)
    extra_bytes=mess_length%IV_len
    print "Extra Bytes: " + str(extra_bytes)
    padd_bytes=IV_len-extra_bytes
    print "Padd Bytes: " + str(padd_bytes)
    
    for x in range(0,padd_bytes):
        msg+="{:02x}".format(padd_bytes)

    return msg

def cbc(previous, next):
    temp = strxor(previous.decode('hex'),next.decode('hex'))
    aes = AES.new(key)
    return aes.encrypt(temp).encode('hex')

def encryption(msg):
    length = len(msg)
    num_mess = length/len(key.encode('hex'))
 
    temp=msg[0:32]
    for x in range(0,num_mess):
        temp+=cbc(temp[x*32:(x+1)*32],msg[x*32:(x+1)*32])

    return temp



def main():
    print "Message: \t\t" + MSGS[0]    

    print "IV: \t\t\t" + IV.encode('hex')
    prepared=padd(MSGS[0])
    print "Prepared Message: \t" + prepared
    print "KEY: \t\t\t" + key.encode('hex')
    
    print "My Encryption: \t\t" + encryption(prepared)
    
    aes=AES.new(key,AES.MODE_CBC, IV)
    print "Python Encryption: \t" + IV.encode('hex') + aes.encrypt(prepared.decode('hex')).encode('hex')

    O = open('Encrypted Text.txt','w')    
    for msg in MSGS:
        O.write(encryption(prepared)+ "\n")
    
if __name__ == "__main__":
    main()
