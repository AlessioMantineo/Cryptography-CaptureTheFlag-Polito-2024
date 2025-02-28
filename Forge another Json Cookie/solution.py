import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
#CRYPTO24{f72bbe86-479a-4208-a187-c1cf4c2284b9}
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from pwn import *

HOST = "130.192.5.212"
PORT = 6551

'''
{"username": "AA
True}AAAAAAAAAAA
AAAA", "admin": 
AAA", "admin": F
alse}
'''

'''
{"username": "AA
True}AAAAAAAAAAF
alse}AAAAAAAAAAA
AAAA", "admin": 
alse}
'''

'''
{"username": "AA
{'admin': True}
", 'admin': Fals
e}
'''

'''
{"username": "AA{'admin': True}", 'admin': False}
'''

# username = b"A"*3 + b"True}" + b"A"*11 + b"A"*4 + b"'" + b"," + b" 'admin': " +b"A"*3

# username = b"A"*3 + pad(b"True }", AES.block_size) + b"A"*4

# username = b"A"*2 + pad(b"{'admin': True}", AES.block_size)
# username = b"A"*2 +b"'" + b"{\"admin\": true, " + b"\"a\": 1000}'" + b"AAAAAAAAAAAAAA"
# username = b"AA" + b"AAAAAAAAAAAAAA: " + b"True," + b"           " + b"               " + b"\"aaaaaaaaaaaaaaa" + b"               \"" + b"" + b":              " + b"    "
# username = b"AA" + b"true," + b"           " + b"               " + b"\"aaaaaaaaaaaaaaa" + b"               \"" + b"" + b":              " + b"    "
username = b"AA" + b"true," + b"           " + b"               " + b"\"aaaaaaaaaaaaaaa" + b"               \"" + b"" + b":              " + b"AAAA"
"""
123456789ABCDEFG
{"USERNAME": AA    B1
TRUE,___________   B2
_______________\   B3
"AAAAAAAAAAAAAAA   B4
_______________\   B5
":______________   B6
AAAA, "ADMIN": F   B7
FALSE              B8   

b = b1 + b7 + b2 + b4 + b6 + b8
{"USERNAME": AAAAAA, "ADMIN": TRUE,"AAAAAAAAAAAAAAA":FALSE
"""
# t = json.dumps({
#     "usename": username.decode(),
#     "admin": False
# })

print(username)


# print(len(t))

# print([t[i: i + 16] for i in range(0, len(t), 16)])

server = remote(HOST, PORT)

try:
    server.recvuntil(b"> ")
    server.sendline(username)
    server.recvuntil(b"This is your token:")
    token = server.recvline().strip()
    print(f"token: {token}")
    print(f"len token: {len(token)}")

    b64_token_decode = base64.b64decode(token)
    print(f"token decoded: {b64_token_decode}")
    print(f"len token decode: {len(b64_token_decode)}")

    # b1 = b64_token_decode[:16]
    # b2 = b64_token_decode[16:32]
    # b3 = b64_token_decode[32:48]
    # b4 = b64_token_decode[48:64]


    # b = b1 + b2 + b3 + b2[:6] + b4[6:]

    b1 = b64_token_decode[:16]
    b2 = b64_token_decode[16:32]
    b3 = b64_token_decode[32:48]
    b4 = b64_token_decode[48:64]
    b5 = b64_token_decode[64:80] 
    b6 = b64_token_decode[80:96]
    b7 = b64_token_decode[96:112]
    b8 = b64_token_decode[112:128]

    print("b1", len(b1))
    print("b2", len(b2))
    print("b3", len(b3))
    print("b4", len(b4))
    print("b5", len(b5))
    print("b6", len(b6))
    print("b7", len(b7))
    print("b8", len(b8))


    # b = b2 + b3 + b6
    # b = b1 + b8 + b3 + b5 + b7 + b9
    b = b1 + b7 + b2 + b4 + b6 + b8

    # print(b)
    # print(len(b))
    print(f"b decoded: {b}")
    print(f"len b decoded: {len(b)}")
    b64_forge_token = base64.b64encode(b)
    print(f"len token forge: {len(b64_forge_token)}")
    print(b64_forge_token)

    server.recv(1024)
    server.sendline(b"flag")
    server.recv(1024)
    server.sendline(b64_forge_token)
    print(server.recv(1024))
    print(server.recv(1024))
except Exception as e:
    print(f"An error occurred: {e}")

server.close()