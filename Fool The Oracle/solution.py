import os

# Suppress pwnlib terminal warnings
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *  # Import the pwntools library for interaction with the server
from string import ascii_lowercase

try:
    '''
    - The flag is 46 characters long.
    - The encryption is done in 32-byte blocks.
    - The attacker needs to align the flag properly in the blocks.
    '''

    # Start with the known flag prefix
    flag = "CRYPTO24{"
    flag_len = len(flag)

    # Calculate the number of padding bytes needed to align the flag
    start = 64 - flag_len - 1  # Adjusting to place the flag in a known position

    # Connect to the challenge server
    server = remote('130.192.5.212', 6541)

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
            tb = b"A" * start  # Fill with additional "A"s for alignment
            message = fb + sb + tb
            message_hex = message.hex()  # Convert to hexadecimal format

            # Send the crafted message for encryption
            server.sendline(message_hex.encode())

            # Receive and decode the encrypted response
            ciphertext = server.recvline().strip()
            ciphertext_str = bytes.fromhex(ciphertext.decode())

            # Check if the second and third blocks are identical (ECB mode pattern leakage)
            if (ciphertext_str[:64] == ciphertext_str[64:128]):
                # If the blocks match, we found the correct character
                flag += guess
                start -= 1  # Reduce padding as we reveal more of the flag
                print(flag)

                # Stop when the flag is completely recovered
                if guess == "}":
                    break

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    # Close the connection to the server
    server.close()
