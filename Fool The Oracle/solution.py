
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from string import printable

try:
    '''
    46 flag length
    32 blocks 
    14 + 2
    '''

    # flag = "CRYPTO24{59e08-2fc4-4eff"
    flag = "CRYPTO24{"
    flag_len = len(flag)
    start = 64 - flag_len - 1

    server = remote('130.192.5.212', 6541)

    dict = "{}0123456789-" + string.ascii_lowercase

    while True:
        for guess in dict:
            # print(f"guess: {guess}")
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

            # message = b"A"*start + flag.encode() + guess.encode() + b"A"*start
            fb = b"A" * start
            sb = flag.encode() + guess.encode()
            tb = b"A" * start
            message = fb + sb + tb
            message_hex = message.hex()

            # print(f"message to send: {message_hex}")

            server.sendline(message_hex.encode())

            ciphertext = server.recvline().strip()
            # print(f"ciphertext len {len(ciphertext)}")
            ciphertext_str = bytes.fromhex(ciphertext.decode())
            # print(f"ciphertext: {ciphertext_str.hex()}")
            # print(f"first block: {ciphertext_str[:32].hex()}")
            # print(f"second block: {ciphertext_str[32:64].hex()}")
            # print(f"third block: {ciphertext_str[64:96].hex()}")
            # print(f"fourth block: {ciphertext_str[96:128].hex()}")
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
