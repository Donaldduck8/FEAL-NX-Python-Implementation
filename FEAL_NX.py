'''
Created on 01.07.2019

@author: Donald
'''
import re
from builtins import ValueError

#Using integer lists as unsigned byte sequences#

def verifyListsToContainBytes(*lists):
    if(len(list(lists)) == 0):
        return
    for toVerify in list(lists):
        if(min(toVerify) < 0 or max(toVerify) > 255):
            print(toVerify)
            print("Found list %d with overflown values" % list(lists).index(toVerify))
            raise ValueError
       
def verifyHexString(string):
    #Defensive programming
    if len(string) == 0:
        print("verifyHexString() called with empty string")
        raise ValueError
	
    #Regex pattern that matches any non-hexadecimal characters
    pattern = re.compile("[^0-9A-Fa-f]")
    if pattern.search(string):
        raise ValueError

def hexStringToIntList(string):
    #Defensive programming
    verifyHexString(string)
    if len(string) == 0 or len(string) % 2 != 0:
        raise ValueError
    
    #Initialize variables
    index = 0
    ret = [0] * int(len(string) / 2)
    
    #Convert two numbers to 1 byte at a time
    while(index < len(string)):
        #TODO Ugly
        substring = string[index:index+2]
        ret[int(index/2)] = int(substring, 16)
        index += 2
        
    #Defensive programming
    verifyListsToContainBytes(ret)
    
    return ret

def intListToHexString(ints):
    #Defensive programming
    verifyListsToContainBytes(ints)
    
    ret = ""
    for int in ints:
        ret = ret + ("%02X" % int)
        
    #Defensive programming
    verifyHexString(ret)
    
    return ret        
    
def Fk(a, b):
    #Defensive programming
    verifyListsToContainBytes(a, b)
    if(len(a) != 4 or len(b) != 4):
        print("Fk() called with invalid arguments")
        raise ValueError
    
    ret = [0] * 4
    ret[1] = S(a[0]^a[1], b[0]^a[2]^a[3], 1)
    ret[0] = S(a[0], b[2]^ret[1], 0)
    ret[2] = S(a[2]^a[3], b[1]^S(a[0]^a[1], b[0]^a[2]^a[3], 1), 0)
    ret[3] = S(a[3], b[3]^ret[2], 1)
    
    #Defensive programming
    verifyListsToContainBytes(ret)
    
    return ret
    
def F(a, b):
    #Defensive programming
    verifyListsToContainBytes(a, b)
    if(len(a) != 4 or len(b) != 2):
        print("F() called with invalid arguments")
        raise ValueError
    
    ret = [0] * 4
    T = a[3]^a[2]^b[1]
    ret[1] = S(a[0]^a[1]^b[0], T, 1)
    ret[0] = S(a[0], ret[1], 0)
    ret[2] = S(T, ret[1], 0)
    ret[3] = S(ret[2], a[3], 1)
    
    #Defensive programming
    verifyListsToContainBytes(ret)
    
    return ret
    
def S(A,B,D):
    #Defensive programming
    if A not in range(0, 256) or B not in range(0, 256) or D not in range(0,2):
        print("S() called with invalid arguments")
        raise ValueError
    
    T = A + B + D % 256
    
    #Rotate T left by 2
    T2 = testBitInInteger(T,7)
    T3 = testBitInInteger(T,6)
    
    T = T << 2
    T = T % 256
    if T2 != 0:
        T = T + 2
        
    if T3 != 0:
        T = T + 1
    
    #Defensive programming
    if T not in range(0,256):
        print("S() returned invalid values")
        raise ValueError
    
    return T
    
def testBitInInteger(T, offset):
    #Defensive programming
    if offset < 0 or offset > 256:
        print("testBitInInteger() called with invalid arguments")
        raise ValueError
    
    #Return 1 if bit at offset is 1
    mask = 1 << offset
    val = T & mask
    if val != 0:
        return 1
    else:
        return 0
    
def XOR(a,b):
    #Defensive programming
    verifyListsToContainBytes(a,b)
    if len(a) != len(b) or len(a) < 0:
        print("XOR() called with invalid arguments")
        raise ValueError
    
    #XOR individual elements of both lists
    ret = [0] * len(a)
    for i in range(0, len(a)):
        ret[i] = a[i] ^ b[i]
    
    #Defensive programming
    verifyListsToContainBytes(ret)
    
    return ret
    
def EncryptFEALNX(PlainText, Key, numberOfRounds):
    #Defensive programming
    verifyListsToContainBytes(PlainText, Key)
    if len(PlainText) != 8 or len(Key) != 16 or numberOfRounds <= 0:
        print("EncryptFEALNX() called with invalid arguments")
        raise ValueError
    
    #Initialization
    subkeys = KeyGeneration(Key, numberOfRounds)
    FirstXOR = subkeys[2*numberOfRounds: 2*numberOfRounds + 8]
    PlainText = XOR(PlainText, FirstXOR)
    LCurrent = PlainText[0:4]
    RCurrent = PlainText[4:8]
    RCurrent = XOR(LCurrent, RCurrent)
    
    #Core Loop
    for i in range(0,numberOfRounds):
        LCurrent = XOR(LCurrent, F(RCurrent, subkeys[2*i:2*i+2]))
        LCurrent, RCurrent = RCurrent, LCurrent
    
    #Last XOR
    LastXOR = subkeys[2*numberOfRounds + 8: 2*numberOfRounds + 16]
    LCurrent = XOR(LCurrent, RCurrent)
    CipherText = RCurrent + LCurrent #Notice that LCurrent and RCurrent switch positions
    CipherText = XOR(LastXOR, CipherText)
    return CipherText

def DecryptFEALNX(CipherText, Key, numberOfRounds):
    #Defensive programming
    verifyListsToContainBytes(CipherText, Key)
    if len(CipherText) != 8 or len(Key) != 16 or numberOfRounds <= 0:
        print("EncryptFEALNX() called with invalid arguments")
        raise ValueError
    
    #Initialization
    subkeys = KeyGeneration(Key, numberOfRounds)
    FirstXOR = subkeys[2*numberOfRounds + 8: 2*numberOfRounds + 16]
    CipherText = XOR(CipherText, FirstXOR)
    #Notice that LCurrent is the right half of CipherText, and RCurrent is the left half
    LCurrent = CipherText[4:8]
    RCurrent = CipherText[0:4]
    LCurrent = XOR(LCurrent, RCurrent)
    
    #Core Loop
    for i in range(numberOfRounds-1, -1, -1):
        LCurrent, RCurrent = RCurrent, LCurrent
        LCurrent = XOR(LCurrent, F(RCurrent, subkeys[2*i:2*i+2]))
       
    #Last XOR 
    LastXOR = subkeys[2*numberOfRounds: 2*numberOfRounds + 8] #TODO Check this
    RCurrent = XOR(LCurrent, RCurrent)
    PlainText = LCurrent + RCurrent
    PlainText = XOR(PlainText, LastXOR)
    return PlainText

def KeyGeneration(Key, numberOfRounds):
    #Defensive programming
    verifyListsToContainBytes(Key)
    if len(Key) != 16 or numberOfRounds <= 0:
        print("KeyGeneration() called with invalid parameters")
        raise ValueError
    
    #Initialization
    subKeys = [0] * 2*(numberOfRounds+4)
    ACurrent = Key[0:4]
    BCurrent = Key[4:8]
    XORTemp = [0] * 4
    XORResult = [0] * 4
    KR1 = Key[8:12]
    KR2 = Key[12:16]
    KRX = XOR(KR1, KR2)
    
    #Core Loop
    for i in range(0, int(numberOfRounds/2+4)):
        if(i % 3 == 0):
            XORResult = XOR(BCurrent, KRX)
        elif(i % 3 == 1):
            XORResult = XOR(BCurrent, KR1)
        else:
            XORResult = XOR(BCurrent, KR2)
            
        if(i > 0):
            XORResult = XOR(XORResult, XORTemp)
        
        XORTemp = ACurrent[0:4]
        ACurrent = Fk(ACurrent, XORResult)
        
        subKeys[4 * i: 4 * i + 2] = ACurrent[0:2]
        subKeys[4 * i + 2: 4 * i + 4] = ACurrent[2:4]
        
        ACurrent, BCurrent = BCurrent, ACurrent
    
    return subKeys
    
def testFunction():
    PT = hexStringToIntList("0000000100020003")
    print("PT: " + intListToHexString(PT))
    K = hexStringToIntList("000102030405060708090A0B0C0D0E0F")
    print("K: " + intListToHexString(K))
    CT = EncryptFEALNX(PT, K, 32)
    print("CT: " + intListToHexString(CT))
    DT = DecryptFEALNX(CT, K, 32)
    print("DT: " + intListToHexString(DT) + "\n\n")
    
    #Print key
    print("KEY = " + intListToHexString(K))
    for k in range(0, 10):
        for i in range(0, 4096):
            #Calculate CT
            CT = EncryptFEALNX(PT, K, 32)
            #Print line
            print("PT: " + intListToHexString(PT) + ",  CT: " + intListToHexString(CT))
            #Increment PT
            for j in range(0,len(PT)):
                if j % 2 == 0:
                    if PT[j+1] == 255:
                        PT[j] += 1
                else:
                    if PT[j] == 255:
                        PT[j] = 0
                    else:
                        PT[j] += 1
            
        #Stop after end of 10th round
        if(k == 9):
            break
            
        #Shift Key left by 1, append next highest byte
        for i in range(0, len(K) - 1):
            K[i] = K[i+1]
        K[-1] = K[-2] + 1
        
        #Reset PT
        PT = hexStringToIntList("0000000100020003")
        
        #Print spacer
        print()
        
        #Print key
        print("KEY = " + intListToHexString(K))
        
if __name__ == '__main__':
    testFunction()