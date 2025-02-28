"""
FACENDO XOR TRA CIPEHR TEXT E OLD COOKIE OTTENGO KEYSTREAM
POI USO KEYSTREM PER FARE ENCRYPT CON NUOVO COOKIE
"""
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

import base64
import json

from pwn import *

HOST = "130.192.5.212"
PORT = 6521

name = "ale"

old_cookie = json.dumps({
    "username": name
})

new_cookie = json.dumps({
    "admin": True,
})
#Connessione al server
server = remote(HOST, PORT)

try:
    """
    Generazione del token: 
    Il server genera un token
    """
    server.sendline(name.encode())
    server.recvuntil(b"This is your token:")
    full_token = server.recvline().decode()
    
    """
    Decodifica del token: 
    Il token ricevuto viene decodificato dal formato base64 
    e separato in nonce e contenuto cifrato.
    """
    nonce, token = full_token.split(".")
    b64_token_decode = base64.b64decode(token)
    #Non conosco il Keystream
    """
    Manipolazione del token: 
    manipolazione XOR bit a bit sul 
    contenuto cifrato del token (ciphertext) per convertire 
    il vecchio cookie (old_cookie) [mi serve tutta la stringa 
    perchè encript fatto su json] 

    in un keystream che può essere utilizzato per criptare un 
    nuovo cookie (new_cookie) 
    con il campo "admin" impostato su True.
    """

    keystream = bytearray(b64_token_decode)
    #conosco il keystream


    for i in range(len(old_cookie)):
        keystream[i] = ord(old_cookie[i]) ^ b64_token_decode[i]

    edt_token = bytearray(b64_token_decode)

    """
    Creazione del nuovo token: 
    Utilizzando il keystream ottenuto dalla manipolazione,  
    nuovamente un'operazione XOR bit a bit 
    per criptare il nuovo cookie 
    con il campo "admin" impostato su True.
    """
    #voglio mettere ADMIN=true
    #faccio for che cicla per nuemro caratteri new cookie
    #xor tra new cookie e keystream calcolato prima
    #nuovo token (lunghezza minore)
    for i in range(len(new_cookie)):
        edt_token[i] = ord(new_cookie[i]) ^ keystream[i]
    
    edt_token = edt_token[:len(new_cookie)]
    new_full_token = nonce + "." + base64.b64encode(edt_token).decode()

    server.recv(1024)
    #Richiesta della flag
    server.sendline(b"flag")
    server.recv(1024)
    """
    Invio del nuovo token al server: 
    Il nuovo token manipolato viene inviato al server come se fosse 
    il token originale.
    """
    server.sendline(new_full_token.encode())
    flag = server.recv(1024)
    #Ricezione della flag
    print(f"flag: {flag.decode()}")
except Exception as e:
    print(f"An error occurred: {e}")

server.close()
    