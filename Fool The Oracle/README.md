# Cryptography CaptureTheFlag Polito 2024
# AES ECB Encryption Challenge - Writeup & Solution

## Challenge Overview
This challenge involves a service that encrypts user-provided input along with a secret flag using **AES in ECB mode**. Due to a **known weakness of ECB mode**, an attacker can recover the flag by leveraging a **block-alignment attack**.

### Challenge Description
The server implements an AES encryption function where:

1. **AES-ECB Mode is Used (Electronic Codebook Mode)**:
   - ECB mode encrypts each block **independently**, meaning identical plaintext blocks produce identical ciphertext blocks.
   - This allows an attacker to detect repeating patterns.

2. **Controlled Input is Concatenated with the Flag**:
   - The user can input arbitrary data which is then **prepended to the flag** before encryption.
   - This allows the attacker to manipulate plaintext alignment.

3. **No Random IV or Salting**:
   - The encryption function does not use a random **Initialization Vector (IV)** or **Salt**, meaning the same plaintext will always produce the same ciphertext.

---

## Vulnerable Code Analysis
### Server Code (Vulnerable Implementation)
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from secret import flag

assert(len(flag) == len("CRYPTO23{}") + 36)

key = get_random_bytes(24)
flag = flag.encode()

def encrypt() -> bytes:
    data  = bytes.fromhex(input("> "))
    payload = data + flag

    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())

def main():
    menu = (
        "What do you want to do?\n"
        "quit - quit the program\n"
        "enc - encrypt something\n"
        "help - show this menu again\n"
        "> "
    )
    
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "enc":
            encrypt()

if __name__ == '__main__':
    main()
```

### Key Vulnerabilities
1. **AES-ECB Mode Used Without a Random IV**:
   - Each block is encrypted independently, allowing pattern recognition.
   
2. **User Input Directly Concatenated with the Flag**:
   - The attacker can precisely control plaintext block alignment.

3. **Padding is Predictable**:
   - AES uses **PKCS#7 padding**, making it easier to infer data structure.

---

## Exploit Strategy
### How to Break the Encryption
1. **Detect Block Size**:
   - By sending increasing input lengths, the attacker determines the block size (16 bytes for AES).

2. **Align the Flag with a Known Input**:
   - The attacker crafts input so that the first block contains only controlled data.
   - This allows comparison of **plaintext-ciphertext mappings**.

3. **Brute-Force the Flag Character by Character**:
   - The attacker tries all possible characters, appending them to a known flag prefix.
   - If two ciphertext blocks match, the guessed character is correct.

---

## Solution Code (Exploit)
```python
import os
from pwn import *
from string import ascii_lowercase

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

try:
    # Partial flag initialization
    flag = "CRYPTO24{"
    flag_len = len(flag)
    start = 64 - flag_len - 1  # Adjust block alignment

    server = remote('130.192.5.212', 6541)
    vocabulary = "{}0123456789-" + ascii_lowercase

    while True:
        for guess in vocabulary:
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

            # Constructing the input to align the flag in a predictable block
            fb = b"A" * start  # Fill first block
            sb = flag.encode() + guess.encode()  # Add flag + guessed character
            tb = b"A" * start  # Padding to force repetition
            message = fb + sb + tb
            message_hex = message.hex()

            server.sendline(message_hex.encode())
            ciphertext = server.recvline().strip()

            ciphertext_str = bytes.fromhex(ciphertext.decode())

            # Check if the second and third encrypted blocks are the same
            if (ciphertext_str[:64] == ciphertext_str[64:128]):
                flag += guess
                start -= 1
                print(flag)
                if guess == "}":
                    break

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    server.close()
```

---

## Why Does This Work?
1. **ECB Mode Leaks Patterns**:
   - Since ECB encrypts identical plaintext blocks into identical ciphertext blocks, the attacker can compare results.

2. **Controlled Input Allows Alignment**:
   - The attacker forces the flag into a known block position by padding with chosen characters.

3. **Matching Ciphertext Blocks Reveal Characters**:
   - The attacker brute-forces each character and checks if the resulting ciphertext **matches the known flag encryption**.


