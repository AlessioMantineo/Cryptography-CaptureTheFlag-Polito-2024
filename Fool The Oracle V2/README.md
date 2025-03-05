# Cryptography CaptureTheFlag Polito 2024
# AES ECB Encryption Challenge (with Random Padding) - Writeup & Solution

## Challenge Overview
This challenge involves a service that encrypts user-provided input along with a secret flag using **AES in ECB mode**. However, unlike the previous challenge, this version introduces a **random padding** before the user input and flag. Despite this, **the vulnerability remains**, and the flag can still be extracted using a **block-alignment attack**.

### Challenge Description
The server implements an AES encryption function where:

1. **AES-ECB Mode is Used (Electronic Codebook Mode)**:
   - ECB mode encrypts each block **independently**, meaning identical plaintext blocks produce identical ciphertext blocks.
   - This allows an attacker to detect repeating patterns.

2. **Controlled Input is Concatenated with a Flag and Random Padding**:
   - The user can input arbitrary data which is then **placed after a random 5-byte padding and before the flag**.
   - The random padding shifts the flag's position but does **not prevent an ECB attack**.

3. **No Random IV or Salting**:
   - The encryption function does not use a random **Initialization Vector (IV)** or **Salt**, meaning the same plaintext will always produce the same ciphertext when aligned correctly.

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
padding = get_random_bytes(5)  # Random 5-byte padding
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
   
2. **User Input Directly Concatenated with Random Padding and Flag**:
   - The attacker can manipulate the plaintext structure to align the flag into known positions.

3. **Padding Does Not Prevent the Attack**:
   - Although the flag is shifted, it still aligns with ECB blocks, allowing for an attack.

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
    '''
    - The flag is 46 characters long.
    - AES encryption is done in 32-byte blocks.
    - The attack exploits ECB mode weaknesses by aligning known inputs with the flag.
    '''

    flag = "CRYPTO24{"  # Known flag prefix
    flag_len = len(flag)

    # Adjust padding for alignment with the encrypted flag position
    start = 91 - flag_len - 1
    second_start = 64 - flag_len - 1

    # Connect to the challenge server
    server = remote('130.192.5.212', 6542)

    # Define possible characters for brute-force guessing
    vocabulary = "{}0123456789-" + ascii_lowercase

    while True:
        for guess in vocabulary:
        
            # Send the "enc" command to request encryption
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

            # Construct a message to align the flag properly in the AES-ECB encryption
            fb = b"A" * start  # Fill first block with "A"
            sb = flag.encode() + guess.encode()  # Append the known flag + guessed character
            tb = b"A" * second_start  # Fill with additional "A"s for alignment

            message = fb + sb + tb
            message_hex = message.hex()  # Convert to hexadecimal format

            # Send the crafted message for encryption
            server.sendline(message_hex.encode())

            # Receive and decode the encrypted response
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

2. **Controlled Input Allows Alignment**:
   - The attacker forces the flag into a known block position by padding with chosen characters.

3. **Matching Ciphertext Blocks Reveal Characters**:
   - The attacker brute-forces each character and checks if the resulting ciphertext **matches the known flag encryption**.

---