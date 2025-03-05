# Import necessary modules
import os
from string import ascii_lowercase

# Suppress pwnlib terminal warnings
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *  # Import the pwntools library for interaction with the server

# Target server information
HOST = "130.192.5.212"
PORT = 6561

# Partial flag initialization
# The flag format is known, and we start with a known prefix
flag = b"CRYPTO24{"  

# Character set to brute-force the flag
vocabulary = "{}0123456789-" + ascii_lowercase

# Connect to the challenge server
server = remote(HOST, PORT)

try:
    # Receive the initial prompt and send a fixed seed to control nonce generation
    server.recvuntil(b"Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> ")
    server.sendline(b"2")  # Choosing a fixed seed for predictable nonce behavior

    # Receive confirmation and encrypted flag
    server.recvline()  
    flag_enc = server.recvline().strip()
    print(f"flag enc: {flag_enc.decode()}")  # Print encrypted flag
    flag_enc_len = len(flag_enc)  
    print(f"len of flag enc: {flag_enc_len}")  # Print encrypted flag length

    # Convert hex-encoded flag encryption into bytes
    flag_hex = bytes.fromhex(flag_enc.decode())  
    flag_hex_len = len(flag_hex)

    """
    Attack strategy:
    - We know that the server reuses the same nonce for every encryption.
    - We send the known flag prefix with one additional guessed character.
    - If the encrypted result matches the prefix of the encrypted flag, 
      then the guessed character is correct.
    """

    while flag.decode()[-1] != "}":  # Continue until the full flag is found
        i = len(flag) + 1  # Expected length of the encrypted message
        for c in vocabulary:  # Iterate through possible characters
            server.recv()
            server.sendline(b"y")  # Confirm we want to encrypt another message
            server.recv(1024)
            msg = flag + c.encode()  # Append the guessed character
            server.sendline(msg)  # Send the message
            enc = server.recvline().strip()  # Receive encrypted response

            # If the first i bytes of the flag encryption match, we found the correct character
            if flag_hex[:i].hex().encode() == enc:
                flag += c.encode()  # Append the correct character to the flag
                i += 1
                print(f"flag: {flag.decode()}")  # Print progress

except Exception as e:
    print(f"An error occurred: {e}")  # Handle exceptions

server.close()  # Close the connection to the server
