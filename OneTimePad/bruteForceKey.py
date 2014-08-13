'''
Created on Aug 5, 2014

@author: root
'''

import sys


#Strings have to be decoded if the string is in hex
def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])
   
def search(i,j,MSGS):
    crount=0
    for x in xrange(0,256):
        k = "{:02x}".format(x)
        
        
        
        count = 0

        for m in MSGS:
            temp=strxor(m[i:j].decode('hex'),k[i:j].decode('hex'))

            if ((temp >= "20".decode('hex')) and (temp <= "7e".decode('hex'))):
                count+=1
            if count > len(MSGS)-1:
                print "stop: " + k
                crount+=1
                print crount
                print
                #return k

def findKey(MSGS):
    key=""
    for x in range(0,1024,2):
        print x
        key += search(x,x+2,MSGS)
        
    return key
    
def main():
    MSGS = []
    I = open('Encrypted.txt', 'r')
    #K = open('FoundKey.txt','w')
    
    for line in I:
        MSGS.append(line.rstrip('\n'))
        
    #print findKey(MSGS)
    #K.write(findKey(MSGS) + "\n")
    search(0,2,MSGS)

if __name__ == "__main__":
    main()
    
