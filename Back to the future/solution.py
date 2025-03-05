import requests
import time
import random
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Target server URL
url = "http://130.192.5.212:6522"
# Username to be used for login
username = "al3m3"

# Start a new session to maintain cookies and other session data
s = requests.Session()

# Perform a GET request to the login endpoint with admin access request
r = s.get(f"{url}/login", params={"username": username, "admin": "1"}).json()

# Extract the encrypted session cookie and nonce from the response
cookie = r["cookie"]
nonce = r["nonce"]

# Print retrieved cookie and nonce values for debugging
print(f"cookie: {cookie}")
print(f"nonce: {nonce}")

# Convert the received cookie and nonce from integers to bytes
cookie_bytes = long_to_bytes(cookie)
nonce_bytes = long_to_bytes(nonce)

# Calculate the default expiration date (30 days from current time)
expire_date = int(time.time()) + 30 * 24 * 60 * 60
print(f"first date: {expire_date}")

# Construct the original plaintext session string that will be encrypted
c = f"username={username}&expires={expire_date}&admin=1".encode()

# Extract the keystream by XOR-ing the known plaintext with the received ciphertext (cookie)
keystream = bytes([a ^ b for a, b in zip(c, cookie_bytes)])

# Convert the cookie bytes to a mutable byte array
edt_cookie = bytearray(cookie_bytes)

# Loop to generate potential valid expiration timestamps within the required range
for i in range(10, 266):
    # Generate a timestamp within the required valid range (between 290 and 300 days from admin_expire_date)
    x = random.randint(290 * 24 * 60 * 60 + int(time.time()) - i * 24 * 60 * 60, 
                        300 * 24 * 60 * 60 + (int(time.time()) - i * 24 * 60 * 60))
    
    print(f"x: {x}")

    # Convert the generated expiration timestamp to bytes
    expire_date_leak_bytes = str(x).encode()

    # Modify the encrypted cookie by inserting the correct expiration timestamp using the extracted keystream
    for j in range(10):
        edt_cookie[j+23] = expire_date_leak_bytes[j] ^ keystream[j+23]

    # Convert the modified cookie back to an integer for submission
    new_cookie_long = bytes_to_long(bytes(edt_cookie))

    # Send the modified encrypted cookie and nonce to the flag endpoint
    r = s.get(f"{url}/flag", params={"nonce": nonce, "cookie": new_cookie_long})

    # If the server response is not "You have expired!", it means we successfully retrieved the flag
    if r.text != "You have expired!":
        print(f"flag: {r.text}")  # Print the obtained flag
        break  # Stop execution after obtaining the flag
