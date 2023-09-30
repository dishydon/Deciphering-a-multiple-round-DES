# Deciphering-a-multiple-round-DES

Step 1 - Preliminaries 

We first ran an automated script to generate 100 pairs of plaintext-ciphertext to get an idea about the ciphertext-space.

Upon further analysis of these 100 pairs, we figured out that the ciphertext space contained English alphabets f to u ciphertext space contained English alphabets f to u. So we realised that the ciphertext space contained exactly 16 alphabets, suggesting that they might be mapped from 0 to 16 as follows: 

�
−
0000
f−0000 
�
−
0001
g−0001
ℎ
−
0010
h−0010 
�
−
0011
i−0011 
�
−
0100
j−0100 
�
−
0101
k−0101 
�
−
0110
l−0110 
�
−
0111
m−0111 
�
−
1000
n−1000 
�
−
1001
o−1001 
�
−
1010
p−1010 
�
−
1011
q−1011 
�
−
1100
r−1100 
�
−
1101
s−1101 
�
−
1110
t−1110 
�
−
1111
u−1111 

This was also consistent with the message given by the soul which stated the following - "two letters for one byte", i.e. one letter is represented by 4 bits. One letter is represented by 4 bits. 

Step 2 - Encryption System and Method of Attack
 
The spirit mentions that the cryptosystem used is a 4-round or a 6-round DES. We assumed a 
6-round
 
DES
6-round DES encryption system. 

To break this DES, we performed a 
known
 
plaintext
 
attack
known plaintext attack. The plaintexts were generated using the mapping explained above and consisted of alphabets from 
�
f to 
�
u .

We moved forward with the following two 
iterative
 
characteristics
iterative characteristics that might give us the possible answer:

Characteristic 1 - 
(
40080000
,
04000000
)
(40080000,04000000) with probability = 
1
16
16
1
​
 
Characteristic 2 - 
(
00200008
,
00000400
)
(00200008,00000400) with probability = 
1
16
16
1
​
 

We conducted our cryptanalysis using these two characteristics in parallel, so as to increase our chances of success. ( 
NOTE:
NOTE: The characteristics here have been represented in hexadecimal notation)

We ran an automated script  to attack the server with multiple plaintexts and got the needed corresponding ciphetexts. This was done for both the characteristics.

Step
 
3
 
-
 
Partial
 
Key
 
Generation
Step 3 - Partial Key Generation 

Each of the two characteristic would let us find 
30
 
bits
30 bits of 
�
6
K 
6
​
 , which is the notation for the round key for the 
6
�
ℎ
6 
th
  round, corresponding to the 
5
 
S-boxes
5 S-boxes. But as 3 of the S-boxes 
(
�
2
,
�
5
,
�
6
)
(S 
2
​
 ,S 
5
​
 ,S 
6
​
 ) are common for both the characteristics, we only get 
42
 
bits
42 bits of the key. 

The other 
14
 
bits
14 bits of the 
56-bit
 
key
56-bit key are found using brute force (explained later).

Using the mapping given at the start, we converted the ciphertexts corresponding to the plaintext pairs into 
binary
 
notation
binary notation of 
64
64 bits.

Then, we applied the reverse final permutation on them and divided them into two halves to get the values of 
�
6
L 
6
​
  and 
�
6
R 
6
​
  and 
(
�
5
=
�
6
)
(R 
5
​
 =L 
6
​
 ) .  We then apply expansion on 
�
5
R 
5
​
 . 

Since the 
XOR
XOR  of the output of the expansion box is equal to the 
XOR
XOR  of the input of the S-boxes, we know the 
XOR
XOR of the inputs of the S-boxes also.

We do not know the value of 
�
5
L 
5
​
 . However, we do know that the 
XOR
XOR of the outputs of some of the S-boxes equals 
zero
zero, for each characteristic, as specified above. We can use this to find the output 
XORs
XORs of the 6th round (denoted by 
�
′
X 
′
 ) as:

�
′
⊕
�
′
=
�
′
⊕
�
′
⊕
�
′
r 
′
 ⊕e 
′
 =r 
′
 ⊕D 
′
 ⊕c 
′
 
=
�
′
=X 
′
 

Where 
�
′
D′ is 
XOR
XOR output after permutation in the 
4
�
ℎ
4 
th
  round, 
�
′
c′ is 
XOR
XOR input to expansion in the 
3
�
�
3 
rd
  round and 
�
′
e′ is 
XOR
XOR input to expansion.  

Since we know that 
�
′
D′ has some S-boxes with zero 
XOR
XOR values, we can determine the 
XOR
XOR outputs of those corresponding bits after permutation in the 
6
�
ℎ
6 
th
  round. Now, we applied the inverse permutation on this 
XOR
XOR value to get the corresponding output of the S-boxes of the 
6
�
ℎ
6 
th
  round with some probability.

Now, for each of these five S-boxes, we 
iterate
 
over
 
all
 
possible
 
keys
iterate over all possible keys and calculate the inputs as the 
XOR
XOR of the expansion box's output and the key. Then, we apply the respective S-box to each of them and obtain the S-box outputs. 

Finally, we determine whether the 
XOR
XOR of these outputs equals the 
expected
expected value. We 
repeat
repeat this process for 
numerous
 
pairs
 
of
 
plaintexts
numerous pairs of plaintexts and select the key that produces the proper 
XOR
XOR output value of the S-boxes the 
greatest
 
number
 
of
 
times
greatest number of times.

Utilising this, 
30
 
bits
30 bits of the key can be determined (
using
 
the
 
5
 
S-boxes
using the 5 S-boxes) by utilising one of the characteristic.

Using the second characteristic, we identify 
12
 
more
 
bits
12 more bits (
using
 
the
 
two
 
new
 
S-boxes
using the two new S-boxes) and check whether the 
18
 
bits
18 bits of the key corresponding to the three S-boxes shared by the two characteristics are 
identical
identical. If it is not identical, we must increase the number of plaintext pairs and locate the optimal key once more. 

We continue to increase the number of pairs until we find a key that satisfies the S-boxes shared by both characteristics. Following are the keys generated with corresponding frequencies:

For characteristic: 
40
40 
08
08 
00
00 
00
00, 
04
04 
00
00 
00
00 
00
00

Sbox-2 (6-bit key) =  
110011
110011  frequency :  
41
41
Sbox-5 (6-bit key) =  
111101
111101  frequency :  
23
23
Sbox-6 (6-bit key) =  
110000
110000  frequency :  
42
42
Sbox-7 (6-bit key) =  
010101
010101  frequency :  
30
30
Sbox-8 (6-bit key) =  
110110
110110  frequency :  
26
26

For characteristic: 
00
00 
20
20 
00
00 
08
08, 
00
00 
00
00 
04
04 
00
00

Sbox-1 (6-bit key) =  
101101
101101  frequency :  
18
18
Sbox-2 (6-bit key) =  
110011
110011  frequency :  
15
15
Sbox-4 (6-bit key) =  
000111
000111  frequency :  
33
33
Sbox-5 (6-bit key) =  
111101
111101  frequency :  
20
20
Sbox-6 (6-bit key) =  
110000
110000  frequency :  
39
39

We therefore calculated the 
Partial
 
Key
Partial Key as follows: 
['#', '1', '1', '#', '#', '1', '#', '#', '0', '1', '0', '1', '1', '#', '1', '0', '0', '#', '#', '1', '1', '#', '1', '1', '0', '0', '0', '#', '0', '0', '1', '0', '0', '1', '1', '#', '1', '1', '1', '1', '1', '0', '0', '0', '#', '1', '1', '#', '0', '1', '1', '1', '#', '0', '0', '1']

NOTE:
NOTE: '#' denotes unknown key bits.


Step
 
4
 
-
 
Brute
 
Force
Step 4 - Brute Force 

Now that we know 
42
 
bits
42 bits of the key, we may loop over 
2
14
2 
14
  potential 
56-bit
56-bit keys to see whether this key produces the right ciphertext when applied to a plaintext, using the key scheduling approach to obtain the round-wise sub-keys.

Using this, we get the 56-bit key in binary as:

01101110010111100111101100000010011011111000111001110001
01101110010111100111101100000010011011111000111001110001

Applying DES decryption on the password : 
gsrquiiofkflimtskmthgrmqlfsktjis
gsrquiiofkflimtskmthgrmqlfsktjis

Converted to Binary: 
01101111011100100111010101110011011001010111101001100100011011000110011101110011001100000011000000110000001100000011000000110000
01101111011100100111010101110011011001010111101001100100011011000110011101110011001100000011000000110000001100000011000000110000

Decrypted  Password: 
orusezdlgs000000
orusezdlgs000000

After removing the padding of zeroes, we get the final password: 
orusezdlgs
orusezdlgs
