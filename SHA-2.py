# -*- coding: cp1252 -*-
#SHA-2
#My SHA-2-256, this is for educational purposes so it'll be slow.
#If you want to do real encryption go to a proper programmer.
#This stuff would run faster on a GPU because it's mostly
#bitwise operations

#This is the hashing algoritm used by Bitcoin as well as most of
#the internet

#Made for python 3

#Sources:-
#https://en.wikipedia.org/wiki/SHA-2

def text2bin(message):

    output = ''
    for i in message:
        output += bin(ord(i))[2:].zfill(8)

    return output

#bitwise rotation of a number rotdist bits to
#the right inside the field defined by bit_length
def ROR(number, rotdist, bit_length):

    #number = bin(number)[2:]
    #make it a x bit binary number
    a = number.zfill(bit_length)
    #print a
    
    #loop over the number of rotations needed
    for i in range(rotdist):

        #perform one rotation at a time
        b = ''
        #do the loop first. If it were not
        #for the looping we could use pythons
        #internal bitwise shift tools
        b = b + a[bit_length - 1]
        #move all the other elements in the string
        for l in range(bit_length - 1):

            b = b + a[l]
            
        
        #alter a to ensure perminance over
        #all the shifts in the code
        #a = int(b, 2)
        a = b

    #print a
    return a
'''
=================================================
====Now we start the SHA-2 specific functions====
=================================================
'''


#this is the function for padding the message out
#it is the same for SHA1 and SHA2

def padding_function(message):
    
    #first convert the message to a string
    binary_message = text2bin(message)


    #record the initial message length for later
    message_length = len(binary_message)

    #add a one to the end of the message string. Now were in the
    #padding stage
    p = binary_message + '1'

    #extend the length of p until len(p)%512 = 448
    while len(p)%512 != 448:
        p += '0'

    #the final padding step, add the length of the starting message

    p += bin(message_length)[2:].zfill(64)

    block_no = int(len(p)/512)

    #splits the padded message into blocks
    blocks = []
    for i in range(block_no):

        blocks.append(p[i * 512: (i * 512) + 512])

    return blocks

'''
===========================================================
==== These are the functions that are used by the loop ====
===========================================================
'''
#^ = XOR
#& = AND
#� = NOT
#ROR(x, n) = rotate x right by n
#x >> n = right shift x by n


#s0 = ROR(x,7) ^ ROR(x,18) ^ x >> 3
def sigma_0(x):

    sigma0 = int(ROR(bin(x)[2:], 7, 32), 2) ^ int(ROR(bin(x)[2:], 18, 32), 2) ^ (x >> 3)

    return sigma0

#s1 = ROR(x,17) ^ ROR(x,19) ^ x >> 10
def sigma_1(x):

    sigma1 = int(ROR(bin(x)[2:], 17, 32), 2) ^ int(ROR(bin(x)[2:], 19, 32), 2) ^ (x >> 10)

    return sigma1

#e0 = ROR(x,2) ^ ROR(x,13) ^ ROR(x,22)
def Eta_0(x):

    Eta_0 = int(ROR(bin(x)[2:], 2, 32), 2) ^ int(ROR(bin(x)[2:], 13, 32), 2) ^ int(ROR(bin(x)[2:], 22, 32), 2)

    return Eta_0

#e1 = ROR(x,6) ^ ROR(x,11) ^ ROR(x,25)
def Eta_1(x):

    Eta_1 = int(ROR(bin(x)[2:], 6, 32), 2) ^ int(ROR(bin(x)[2:], 11, 32), 2) ^ int(ROR(bin(x)[2:], 25, 32), 2)

    return Eta_1

#Chr = (x & y) ^ (�x & z)
def Chr(x, y, z):
    NOT = 0b11111111111111111111111111111111
    Chr = (x & y) ^ ((x ^ NOT) & z)

    return Chr

#Maj = (x & y) ^ (x & z) ^ (y & z)
def Maj(x, y, z):
    Maj = (x & y) ^ (x & z) ^ (y & z)
    return Maj

'''
=======================================================================
==== These are the big functions that do the major bits of SHA-256 ====
=======================================================================
'''


def gen_keys(block):

    keys = []
    for i in range(16):

        keys.append(int(block[(i * 32) : ((i * 32) + 32)], 2))

    #this is wrong and won't work for longer messages. I NEED TO FIX THIS

    #make 48 new keys using the formula:
    #key[i] = key[i-16] ^ s0(key[i-15]) ^ key[i-7] ^ s1(key[i-2])
    for l in range(16,64):

        S0 = sigma_0(keys[l-15])
        S1 = sigma_1(keys[l-2])

        w = (keys[l-16] + S0) % pow(2,32) 

        w = (w + keys[l-7]) % pow(2,32) 

        w = (w + S1) % pow(2,32) 

        keys.append(w) 

    return keys

'''
=========================================================
==== This is the function that actually does SHA-256 ====
=========================================================
'''

#This is all done in one big function. I probably could break it
#down to make it more readable but fuck it
def SHA_256(message):

    #initialise the first h values
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    #initialise the round constants
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    #convert the message into 512 bit blocks by padding it out
    blocks = padding_function(message)

    for p in blocks:

        #generate the keys to be used. This is where the block
        #actually gets processed. Everything else just uses these
        #keys
        keys = gen_keys(p)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        #run the main loop 64 times. You can find a flow diagram for
        #this on wikipedia
        for i in range(64):

            e1 = Eta_1(e)

            ch = Chr(e, f, g)

            e0 = Eta_0(a)

            maj = Maj(a, b, c)

            temp1 = (h + e1) % pow(2, 32)
            temp1 = (temp1 + ch) % pow(2, 32)
            temp1 = (temp1 + k[i]) % pow(2, 32)
            temp1 = (temp1 + keys[i]) % pow(2, 32)

            temp2 = (e0 + maj) % pow(2, 32)


            h = g
            g = f
            f = e
            e = (d + temp1) % pow(2, 32)
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % pow(2, 32)



        #save there results by mod adding them to the
        #previous results
        h0 = (h0 + a) % pow(2, 32)
        h1 = (h1 + b) % pow(2, 32)
        h2 = (h2 + c) % pow(2, 32)
        h3 = (h3 + d) % pow(2, 32)
        h4 = (h4 + e) % pow(2, 32)
        h5 = (h5 + f) % pow(2, 32)
        h6 = (h6 + g) % pow(2, 32)
        h7 = (h7 + h) % pow(2, 32)


    #convert the results to 32 bit binary words for the final
    #result
    h0 = bin(h0)[2:].zfill(32)
    h1 = bin(h1)[2:].zfill(32)
    h2 = bin(h2)[2:].zfill(32)
    h3 = bin(h3)[2:].zfill(32)
    h4 = bin(h4)[2:].zfill(32)
    h5 = bin(h5)[2:].zfill(32)
    h6 = bin(h6)[2:].zfill(32)
    h7 = bin(h7)[2:].zfill(32)

    #add the results using the endian convention
    result = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
    result = hex(int(result, 2))

    return result
    
'''
=========================================================
==== End of functions, start of code using functions ====
=========================================================
'''



message = 'The quick brown fox jumps over the lazy dog and again and again'


result = SHA_256(message)


print(result)
