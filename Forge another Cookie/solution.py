#CRYPTO24{a13ed257-a77f-4a6a-a389-4cf59ced679a}
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
server = remote('130.192.5.212', 6552)
username = b"A"*7 + pad(b"true", AES.block_size) + b"A"*9

print(server.recv(1024))
server.sendline(username)
print(f"username: {username}")
cookie=server.recvline().strip()


cookie_enc = long_to_bytes(int(cookie.strip().decode()))
print("Cookie: ",cookie_enc)

b1 = cookie_enc[:16]
b2 = cookie_enc[16:32]
b3 = cookie_enc[32:48]
b4 = cookie_enc[48:64]

b = b1 + b2 + b3 + b2
print("Forged cookie:", bytes_to_long(b))
forged_cookie = bytes_to_long(b)
print(server.recv(1024))
server.sendline(b'flag')
server.recvuntil(b"Cookie: ")
server.sendline(str(forged_cookie))
print(server.recv(1024))

server.close()