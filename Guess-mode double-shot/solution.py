#nc 130.192.5.212 6532
from pwn import *
HOST = "130.192.5.212"
PORT = 6532

# Connettiti al server
server = remote(HOST, PORT)

try:
    for i in range(128):
        print(f"Challenge #{i}")
        #  l'OTP dal server
        #server.recvuntil(b"The otp I'm using: ")
        #otp = server.recvline().strip()
        #print(f"The OTP I'm using: {otp.decode()}")
        #server.recvuntil(b"Input: ")
        server.recv(1024)
        input_message = b'A' *64
        server.sendline(input_message) 

        #  testo cifrato dal server
        #server.recvuntil(b"Output: ")
        ciphertext = server.recvline().strip()
        print(f"Encrypted message: {ciphertext.decode()}")

        server.recv(1024)
        input_message1 = b'A' *64
        server.sendline(input_message1) 

        #  testo cifrato dal server
        server.recvuntil(b"Output: ")
        ciphertext1 = server.recvline().strip()
        print(f"Encrypted message: {ciphertext1.decode()}")
        ciphertext = ciphertext.split(b"Output: ")[1].strip()
        print(f"Encrypted: {ciphertext.decode()}")
        print(f"Encrypted1: {ciphertext1.decode()}")

        #  domanda  server  modalità utilizzata
        server.recvuntil(b"What mode did I use? (ECB, CBC)\n")

        #  tentativo al server
        if ciphertext1.decode() == ciphertext.decode():
            mode_guess = b'ECB'
        else:
            mode_guess = b'CBC'
        
        print(f"OP MODE: {mode_guess.decode()}")
        server.sendline(mode_guess)

        #  risposta del server
        response = server.recvline().strip()
        print(response.decode())
    Flag = server.recvline().strip()
    print(f"flag: {Flag.decode()}")
except Exception as e:
    print(f"An error occurred: {e}")

# Chiudi la connessione
server.close()