# README #

In this repo I have recreated the SHA-2 algorithm in python in order to help my understanding of the algorithm's method. The SHA-2 algorithm is a commonly used hashing algorithm.

## IMPORTANT NOTE ##

I am some guy in a room. You should never use the code here for real encryption purposes. I hope it will help you understand the principals of the SHA-2 algorithm but this has not been checked by anyone with any real expertise or training in cryptography.


### Algorithm description ###

The subkeys are generated in exactly the same way as was done for SHA-1.

This is done by first converting the message to binary, then appending a 1 to the message followed by a series of zeros until the length of the message satisfies the requirement:

len(m) % 512 = 448 --- (1)

Now the final padding step is to add the original length of the message expressed in binary to the end of the message resulting in a padded message which can be broken down into 32 bit parts which will be used in the next, key generation step to generate a series of 64, 32 bit keys.

The first keys are the 32 bit padding values we just generated, the rest of the keys are generated using the logic shown below, in which &bigoplus; is a XOR operation:

k<sub>i</sub> = k<sub>i-3</sub> &bigoplus; k<sub>i-8</sub> &bigoplus; k<sub>i-14</sub> &bigoplus; k<sub>i-16</sub>

This value is then rotated left by one position and stored as the new key until 64 keys are generated in total. These keys are then used as the values of W<sub>t</sub> in the compression function shown below.


<p align="center">
<image src='./sha2_compress_function.png' width="800px;"></image>
</p>

The logic for the functional blocks for this diagram are shown below:

Ch(E, F, G) = (E & F) &bigoplus; (!E & G)

&Sigma;<sub>1</sub> = (E >>> 6) &bigoplus; (E >>> 11) &bigoplus; (E >>> 25)

Ma(A, B, C) = (A & B) &bigoplus; (A & C) &bigoplus; (B & C)

&Sigma;<sub>0</sub> = (A >>> 2) &bigoplus; (A >>> 13) &bigoplus; (A >>> 22)

Where >>> represents a right-wise bit rotation, &bigoplus; is a XOR operation, & is an and operation and ! is a NOT operation.

The values for K<sub>t</sub> and the starting values of A-H are also pre-set.

This compression function is run for 64 rounds in order to generate the final output hash.

SHA 224, 512 and 384 all work in the same way to the description in this readme but with different initial values and a slightly modified subkey generation schedule for SHA 512 and 384. 

### Sources ###

* https://en.wikipedia.org/wiki/SHA-2