# Cryptography CaptureTheFlag Polito 2024

# AES ECB Encryption Challenge (with Variable Padding) - Writeup & Solution

## Challenge Overview
This challenge involves a service that encrypts user-provided input along with a secret flag using **AES in ECB mode**. Unlike the previous challenges, this version introduces a **random variable-length padding** before the user input and flag. Despite this, **the vulnerability remains**, and the flag can still be extracted using a **block-alignment attack combined with padding length detection**.

### Challenge Description
The server implements an AES encryption function where:

1. **AES-ECB Mode is Used (Electronic Codebook Mode)**:
   - ECB mode encrypts each block **independently**, meaning identical plaintext blocks produce identical ciphertext blocks.
   - This allows an attacker to detect repeating patterns.

2. **Controlled Input is Concatenated with Random Variable Padding and the Flag**:
   - The user can input arbitrary data which is then **placed after a random 1-15 byte padding and before the flag**.
   - The padding shifts the flag's position, **but does not prevent an ECB attack**.

3. **No Random IV or Salting**:
   - The encryption function does not use a random **Initialization Vector (IV)** or **Salt**, meaning the same plaintext will always produce the same ciphertext when aligned correctly.

---

## Vulnerable Code Analysis
### Server Code (Vulnerable Implementation)
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint
from secret import flag

assert(len(flag) == len("CRYPTO23{}") + 36)

key = get_random_bytes(24)
padding = get_random_bytes(randint(1,15))  # Random 1-15 byte padding
flag = flag.encode()

def encrypt() -> bytes:
    data  = bytes.fromhex(input("> ").strip())
    payload = padding + data + flag  # User input is placed after random padding and before the flag

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
   
2. **User Input Directly Concatenated with Variable Random Padding and Flag**:
   - The attacker can manipulate the plaintext structure to align the flag into known positions.

3. **Padding Does Not Prevent the Attack**:
   - Although the flag is shifted randomly, **it still aligns with ECB blocks**, allowing for an attack.

---

## Exploit Strategy
### How to Break the Encryption
1. **Detect Block Size**:
   - By sending increasing input lengths, the attacker determines the block size (16 bytes for AES).

2. **Determine the Padding Size**:
   - The attacker sends a **fixed input (e.g., 15 bytes of 'A')** and observes how the ciphertext length changes.
   - This helps identify the **exact number of random padding bytes**, allowing alignment.

3. **Align the Flag with a Known Input**:
   - The attacker crafts input so that the first block contains only controlled data.
   - This allows comparison of **plaintext-ciphertext mappings**.

4. **Brute-Force the Flag Character by Character**:
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
    '''
    - The flag follows the format CRYPTO24{...}.
    - AES encryption is done in 32-byte blocks.
    - The attack exploits ECB mode weaknesses by aligning known inputs with the flag.
    - A preliminary test determines the padding size before launching the attack.
    '''

    flag = "CRYPTO24{"  # Known flag prefix
    flag_len = len(flag)

    # Adjust padding for alignment with the encrypted flag position
    start = 83 - flag_len - 1
    second_start = 64 - flag_len - 1

    # Connect to the challenge server
    server = remote('130.192.5.212', 6543)
    test = 0  # Variable to check if padding size is determined
    vocabulary = "{}0123456789-" + ascii_lowercase

    while True:
        for guess in vocabulary:
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

            print(test)  # Debugging step

            if test == 0:
                # First step: determine padding size
                message = b'A' * 15
                message_hex = message.hex()
                server.sendline(message_hex.encode())
                ciphertext = server.recvline().strip()
                ciphertext_str = bytes.fromhex(ciphertext.decode())
                print(len(ciphertext_str))  # Print ciphertext length to determine padding size
                test = 1  # Now proceed with actual flag extraction
            else:
                # Constructing the input to align the flag properly in the AES-ECB encryption
                fb = b"A" * start  # Fill first block with "A"
                sb = flag.encode() + guess.encode()  # Append the known flag + guessed character
                tb = b"A" * second_start  # Fill with additional "A"s for alignment

                message = fb + sb + tb
                message_hex = message.hex()  # Convert to hexadecimal format

                server.sendline(message_hex.encode())
                ciphertext = server.recvline().strip()
                ciphertext_str = bytes.fromhex(ciphertext.decode())

                # Check if the second and third blocks are identical (ECB mode pattern leakage)
                if (ciphertext_str[64:96] == ciphertext_str[128:160]):
                    # If the blocks match, we found the correct character
                    flag += guess
                    start -= 1  # Reduce padding as we reveal more of the flag
                    second_start -= 1  # Adjust secondary padding
                    print(flag)

                    # Stop when the flag is completely recovered
                    if guess == "}":
                        break

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    # Close the connection to the server
    server.close()
```

---

## Why Does This Work?
1. **ECB Mode Leaks Patterns**:
   - Since ECB encrypts identical plaintext blocks into identical ciphertext blocks, the attacker can compare results.

2. **Detecting the Random Padding Length**:
   - Sending a **fixed-length message** helps determine the exact padding size.
   - Once the padding is known, the flag's position can be predicted.

3. **Matching Ciphertext Blocks Reveal Characters**:
   - The attacker brute-forces each character and checks if the resulting ciphertext **matches the known flag encryption**.

---