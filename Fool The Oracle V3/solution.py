#nc 130.192.5.212 6543

import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from string import printable

try:
    '''
    CRYPTO24{5408a811-867e-49bc-86b3-b28090ba89d0}
    '''

    flag = "CRYPTO24{"
    flag_len = len(flag)
    start = 83 - flag_len - 1
    second_start=64-flag_len-1

    server = remote('130.192.5.212', 6543)
    test= 0
    dict = "{}0123456789-" + string.ascii_lowercase

    while True:
        for guess in dict:
        
            #print("> \n")

            # print(f"guess: {guess}")
            server.recvuntil(b"> ")
            server.sendline(b"enc")
            server.recvuntil(b"> ")

            print(test)


            if test == 0:
                message=b'A'*15
                message_hex = message.hex()
                server.sendline(message_hex.encode())
                ciphertext = server.recvline().strip()
                ciphertext_str = bytes.fromhex(ciphertext.decode())
                print(len(ciphertext_str))
                test=1
            else:
                fb= b'A' * start
                sb= flag.encode() +guess.encode()
                tb= b'A' * second_start
                message = fb + sb + tb
                message_hex = message.hex()

                # print(f"message to send: {message_hex}")

                server.sendline(message_hex.encode())

                ciphertext = server.recvline().strip()

                ciphertext_str = bytes.fromhex(ciphertext.decode())
                #print(len(ciphertext_str))
                """
                if len(ciphertext_str) != 174:
                    print("wrong padding size\n")
                    test = 1
                    exit()
                """
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