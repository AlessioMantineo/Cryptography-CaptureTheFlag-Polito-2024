#nc 130.192.5.212 6561
import os
from string import ascii_lowercase

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6561

#flag = b"CRYPTO24{fdf00c66-1a1a-4b80-bccb-9cb689a8070"
flag = b"CRYPTO24{"

vocabulary = "{}0123456789-" + string.ascii_lowercase

server = remote(HOST, PORT)

try:
    server.recvuntil(b"Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> ")
    server.sendline(b"2")
    server.recvline()
    flag_enc = server.recvline().strip()
    print(f"flag enc: {flag_enc.decode()}")
    flag_enc_len = len(flag_enc)
    print(f"len of flag enc: {flag_enc_len}")

    flag_hex = bytes.fromhex(flag_enc.decode())
    flag_hex_len = len(flag_hex)
    """
        noi sappiamo segreto cryptato
        mandiamo al server flag + carattere
        se uguale a segreto cryptato allora
        il carattere è giusto
        (nonce messo male in codice server)
    """

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