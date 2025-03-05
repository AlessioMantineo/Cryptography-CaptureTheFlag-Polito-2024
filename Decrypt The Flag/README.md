# Cryptography CaptureTheFlag Polito 2024

# ChaCha20 Encryption Challenge - Writeup & Solution

## Challenge Overview
This challenge involves a Flask-based service that encrypts a secret flag using the ChaCha20 stream cipher. However, due to an implementation flaw in the nonce management, an attacker can recover the encrypted flag by leveraging a **known-plaintext attack**.

### Challenge Description
The server implements an encryption function that allows users to encrypt messages using ChaCha20. However, there is a critical vulnerability:

1. **Nonce Reuse Issue:** 
   - The function `encrypt_and_update()` is supposed to generate a new random nonce for each encryption. However, it mistakenly does not store or return the new nonce, leading to nonce reuse.
   - Since ChaCha20 is a **stream cipher**, reusing the same nonce with different plaintexts allows an attacker to retrieve the original message.

2. **User-Provided Random Seed:**
   - The server asks the user to provide a seed for the random number generator.
   - This makes nonce generation **predictable**, further weakening the encryption.

3. **Brute-Force Opportunity:**
   - Because nonce reuse enables **plaintext comparisons**, an attacker can brute-force the flag character by character by comparing encrypted outputs.

---

## Vulnerable Code Analysis
### Server Code (Vulnerable Implementation)
```python
import random
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag, randkey

nonce = -1  # Incorrectly initialized nonce

def encrypt_and_update(msg, nonce):
    cipher = ChaCha20.new(key=randkey, nonce=long_to_bytes(nonce))
    nonce = random.getrandbits(12 * 8)  # This does not persist outside the function
    return cipher.encrypt(msg.encode())

def main():
    seed = int(input("Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> "))
    random.seed(seed)  # Makes nonce generation predictable
    nonce = random.getrandbits(12 * 8)

    print("OK! I can now give you the encrypted secret!")
    print(encrypt_and_update(flag, nonce).hex())  # Encrypts the flag

    confirm = input("Do you want to encrypt something else? (y/n)")
    while confirm.lower() != 'n':
        if confirm.lower() == 'y':
            msg = input("What is the message? ")
            print(encrypt_and_update(msg, nonce).hex())  # Encrypts user messages
        confirm = input("Do you want to encrypt something else? (y/n)")

if __name__ == '__main__':
    main()
```

### Key Vulnerabilities
1. **Nonce Mismanagement**:
   - The function `encrypt_and_update()` generates a new nonce but does not persist it.
   - This causes **nonce reuse**, making it possible to compare encrypted outputs.

2. **Predictable Random Seed**:
   - The server allows the user to provide a seed for random number generation.
   - This makes nonce values predictable, which weakens encryption security.

3. **Stream Cipher Weakness**:
   - Since **ChaCha20 is a stream cipher**, when the same nonce is used twice, it results in **XORing two plaintexts together**, revealing information about both.

---

## Exploit Strategy
### How to Break the Encryption
1. **Retrieve the Encrypted Flag**:
   - The attacker first retrieves the encrypted flag from the server.

2. **Use a Known-Plaintext Attack**:
   - The attacker sends **controlled messages** to the server for encryption.
   - Since the same nonce is reused, they can **compare ciphertexts** and infer characters.

3. **Brute-Force Character by Character**:
   - The attacker starts with a known prefix (`CRYPTO24{`).
   - They append different characters from a predefined vocabulary.
   - If the encrypted output matches the flag encryption prefix, the guessed character is correct.

---

## Solution Code (Exploit)
```python
import os
from string import ascii_lowercase
from pwn import *

# Suppress pwnlib terminal warnings
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

# Target server information
HOST = "130.192.5.212"
PORT = 6561

# Partial flag initialization
flag = b"CRYPTO24{"  

# Character set to brute-force the flag
vocabulary = "{}0123456789-" + ascii_lowercase

# Connect to the challenge server
server = remote(HOST, PORT)

try:
    server.recvuntil(b"Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> ")
    server.sendline(b"2")  # Choosing a fixed seed for predictable nonce behavior

    server.recvline()  
    flag_enc = server.recvline().strip()
    flag_hex = bytes.fromhex(flag_enc.decode())  

    while flag.decode()[-1] != "}":  
        i = len(flag) + 1  
        for c in vocabulary:  
            server.recv()
            server.sendline(b"y")  
            server.recv(1024)
            msg = flag + c.encode()  
            server.sendline(msg)  
            enc = server.recvline().strip()  

            if flag_hex[:i].hex().encode() == enc:
                flag += c.encode()  
                i += 1
                print(f"flag: {flag.decode()}")  

except Exception as e:
    print(f"An error occurred: {e}")  

server.close()
```

---

## Why Does This Work?
1. **The server reuses the same nonce** → Enables ciphertext comparisons.
2. **Controlled encryption requests** → We control the plaintext being encrypted.
3. **Matching ciphertexts reveal correct characters** → Character-by-character brute force.




