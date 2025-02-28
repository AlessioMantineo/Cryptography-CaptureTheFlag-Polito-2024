#nc 130.192.5.212 6523
#flag: Good job. Your flag: CRYPTO24{b468978c-869b-4748-affc-b2fc8f883ca9}
"""
AES in modalità CBC. Lo script accetta input 
dall'utente per crittografare o decrittografare dati e 
contiene un valore segreto (leak) che non bisogna crittografare 
o decrittografare direttamente.
"""

"""
durante la decrittografia, lo script controlla se l'IV fornito corrisponde al valore leak. 
Se corrisponde, lo script stampa "Nice try..." e non tenta ulteriori operazioni di decrittografia.
"""
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6523

leak = b"mynamesuperadmin"

try:
    msg = b"A"*32

    server = remote(HOST, PORT)
    server.sendline(b"enc")
    server.recv(1024)
    server.sendline(msg)
    # skip iv:  and Encrypted: 
    iv = server.recvline().strip()[4:]
    enc = server.recvline().strip()[11:]
    print(F"IV: {iv.decode ()}\nEncrypted: {enc.decode()}\n")
    
    print(f"iv: {iv.decode()}")
    print(f"enc: {enc.decode()}")

    # msg xor iv xor iv_leak = mynamesuperadmin -> iv_leak = msg xor iv xor leak
    """
    payload in modo che, quando decifrato con l'IV manipolato, producesse il valore leak (mynamesuperadmin). 
    Per fare ciò, manipolo l'IV in modo tale che quando XOR 
    con il messaggio originale e con il valore leak, il risultato = il valore mynamesuperadmin.
    """

    iv_leak = bytes([a^b^c for a,b,c in zip(bytes.fromhex(msg.decode()), bytes.fromhex(iv.decode()), leak)])


    server.recv(1024)
    server.recv(1024)
    server.sendline(b"dec")
    server.recv(1024)
    server.sendline(enc)
    server.recv(1024)
    server.sendline(iv_leak.hex().encode())
    flag = server.recvline()
    print(f"flag: {flag.decode()}")



except Exception as e:
    print(f"An error occurred: {e}")

finally:
    server.close()