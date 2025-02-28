#nc 130.192.5.212 6542
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

    flag = "CRYPTO24{"
    flag_len = len(flag)
    start = 91 - flag_len - 1
    second_start=64-flag_len-1

    server = remote('130.192.5.212', 6542)

    dict = "{}0123456789-" + string.ascii_lowercase

    while True:
        for guess in dict:
        
            #print("> \n")

            # print(f"guess: {guess}")
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

           

            fb= b'A' * start
            sb= flag.encode() +guess.encode()
            tb= b'A' * second_start
 
            
            message = fb + sb + tb
            message_hex = message.hex()

            # print(f"message to send: {message_hex}")

            server.sendline(message_hex.encode())

            ciphertext = server.recvline().strip()

            ciphertext_str = bytes.fromhex(ciphertext.decode())
            if (ciphertext_str[64:96] == ciphertext_str[128:160]):
                flag += guess
                start -= 1
                second_start-=1
                print(flag)
                if guess == "}":
                    break


except Exception as e:
    print(f"An error occurred: {e}")

finally:
    server.close()
