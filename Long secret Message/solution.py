import numpy
from string import *
from Crypto.Util.strxor import strxor

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

ciphertexts = []

#with open("long_secret_message\\hacker-manifesto.enc", "r") as f:
with open("hacker-manifesto.enc", "r") as f:
    ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]

print(ciphertexts)
print("stats")
print(len(ciphertexts))

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print(len(longest_c))

shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print(len(shortest_c))

candidates_list = []

for byte_to_guess in range(max_len):
    """
    nizializzato con tutti gli elementi impostati su zero usando numpy
    zeros(256, dtype=float). 
    ogni cella dell'array ha un valore 
    iniziale di zero.
    """
    freqs = numpy.zeros(256, dtype=float)

    for guessed_byte in range(256):
        for c in ciphertexts:
            if byte_to_guess >= len(c):
                """
                controlla se l'indice byte_to_guess è maggiore o uguale 
                alla lunghezza del testo cifrato corrente
                """
                continue
            if chr(c[byte_to_guess] ^ guessed_byte) in printable:
                freqs[guessed_byte] += CHARACTER_FREQ.get(chr(c[byte_to_guess] ^ guessed_byte).lower(),0)

    max_matches = max(freqs)

    match_list = [(freqs[i], i) for i in range(256)]
    ordered_match_list = sorted(match_list, reverse=True)
    candidates_list.append(ordered_match_list)



keystream = bytearray()
for x in candidates_list:
    keystream += x[0][1].to_bytes(1,byteorder='big')

dec = keystream[28] ^ ciphertexts[0][1]
mask = dec ^ ord('o')
#keystream[28] = keystream[28]

dec = keystream[28] ^ ciphertexts[3][28]
mask = dec ^ ord('Y')
#keystream[28] = keystream[28] ^ mask

dec = keystream[38] ^ ciphertexts[5][38]
mask = dec ^ ord('i')
#keystream[38] = keystream[38] ^ mask

dec = keystream[40] ^ ciphertexts[5][40]
mask = dec ^ ord('a')
#keystream[40] = keystream[40] ^ mask

dec = keystream[17] ^ ciphertexts[6][17]
mask = dec ^ ord('u')
#keystream[17] = keystream[17] ^ mask

dec = keystream[20] ^ ciphertexts[6][20]
mask = dec ^ ord('u')
#keystream[20] = keystream[20] ^ mask

dec = keystream[65] ^ ciphertexts[1][65]
mask = dec ^ ord('h')
#keystream[65] = keystream[65] ^ mask

dec = keystream[67] ^ ciphertexts[1][67]
mask = dec ^ ord('u')
#keystream[67] = keystream[67] ^ mask

dec = keystream[42] ^ ciphertexts[5][42]
mask = dec ^ ord('s')
#keystream[42] = keystream[42] ^ mask

dec = keystream[43] ^ ciphertexts[1][43]
mask = dec ^ ord('e')
#keystream[43] = keystream[43] ^ mask

dec = keystream[69] ^ ciphertexts[6][69]
mask = dec ^ ord('s')
#keystream[69] = keystream[69] ^ mask

dec = keystream[45] ^ ciphertexts[4][45]
mask = dec ^ ord('u')
#keystream[45] = keystream[45] ^ mask

dec = keystream[46] ^ ciphertexts[4][46]
mask = dec ^ ord('t')
#keystream[46] = keystream[46] ^ mask

dec = keystream[49] ^ ciphertexts[1][49]
mask = dec ^ ord('a')
#keystream[49] = keystream[49] ^ mask

dec = keystream[53] ^ ciphertexts[1][53]
mask = dec ^ ord('e')
keystream[53] = keystream[53] ^ mask

dec = keystream[58] ^ ciphertexts[5][58]
mask = dec ^ ord('m')
keystream[58] = keystream[58] ^ mask

dec = keystream[59] ^ ciphertexts[5][59]
mask = dec ^ ord('i')
keystream[59] = keystream[59] ^ mask 

dec = keystream[28] ^ ciphertexts[7][28]
mask = dec ^ ord('g')
keystream[28] = keystream[28] ^ mask 

for c in ciphertexts:
    l = min(len(keystream),len(c))
    print(strxor(c[:l],keystream[:l]))