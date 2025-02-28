from pwn import *
# The flag is: CRYPTO24{773c8a04-9485-4d54-a166-1e9c079809a4}
# Definisci l'host e la porta del server
HOST = "130.192.5.212"
PORT = 6531

# Connettiti al server
server = remote(HOST, PORT)

try:
    for i in range(128):
        print(f"Challenge #{i}")
        #  l'OTP dal server
        server.recvuntil(b"The otp I'm using: ")
        otp = server.recvline().strip()
        print(f"The OTP I'm using: {otp.decode()}")

        input_message = b'A' *32
        server.sendline(otp) 
        """
        mando OTP al server perchè
        siccome server fa:

        data = bytes([d ^ o for d,o in zip(data,otp)])

        in questo modo la xor darà sempre tutti 0
        (quindi so il plaintext che saranno due blocchi di tutti 0)
        se ECB prima parte uguale a seconda parte
        """

        #  testo cifrato dal server
        server.recvuntil(b"Output: ")
        ciphertext = server.recvline().strip()
        print(f"Encrypted message: {ciphertext.decode()}")



        #  domanda  server  modalità utilizzata
        server.recvuntil(b"What mode did I use? (ECB, CBC)\n")

        #  tentativo al server
        if ciphertext[:32] == ciphertext[32:64]:
            mode_guess = b'ECB'
        else:
            mode_guess = b'CBC'
        #mode_guess = b'ECB'  #  indovina  modalità 
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