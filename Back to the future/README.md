# Cryptography CaptureTheFlag Polito 2024

# Crypto Challenge: ChaCha20 Session Hijacking

### Key Components of the Challenge
- **ChaCha20 Encryption**: The web application encrypts session data using ChaCha20.
- **Session Cookies**: The application generates encrypted cookies containing `username`, `expires`, and `admin` fields.
- **Admin Expiration Check**: The flag is returned only if the `admin` field is set to `1` and the `expires` timestamp meets a specific condition.

## Challenge Breakdown
The web application has two main endpoints:
- `/login`: Accepts `username` and `admin` parameters, then returns an encrypted session cookie along with a nonce.
- `/flag`: Accepts the encrypted cookie and nonce, decrypts the cookie, and checks if the `admin` field is set correctly and the expiration condition is met.

## Solution Approaches
### 1. First Solution (Keystream Manipulation)
This solution leverages the fact that the ChaCha20 cipher operates as a stream cipher, allowing an attacker to manipulate the keystream to modify the encrypted cookie.

#### Steps:
1. Request an admin login to retrieve an encrypted session cookie and nonce.
2. Extract the keystream by XOR-ing the known plaintext with the ciphertext.
3. Modify the expiration date to fall within the required range by XOR-ing the desired timestamp with the extracted keystream.
4. Submit the modified encrypted cookie to the `/flag` endpoint and retrieve the flag.

```python
import requests
import time
import random
from Crypto.Util.number import long_to_bytes, bytes_to_long

url = "http://130.192.5.212:6522"
username = "al3m3"

s = requests.Session()
r = s.get(f"{url}/login", params={"username": username, "admin": "1"}).json()
cookie = r["cookie"]
nonce = r["nonce"]

cookie_bytes = long_to_bytes(cookie)
nonce_bytes = long_to_bytes(nonce)

expire_date = int(time.time()) + 30 * 24 * 60 * 60
c = f"username={username}&expires={expire_date}&admin=1".encode()

keystream = bytes([a ^ b for a, b in zip(c, cookie_bytes)])

edt_cookie = bytearray(cookie_bytes)
for i in range(10, 266):
    x = random.randint(290 * 24 * 60 * 60 + int(time.time()) - i * 24 * 60 * 60, 300 * 24 * 60 * 60 + (int(time.time()) - i * 24 * 60 * 60))
    expire_date_leak_bytes = str(x).encode()

    for j in range(10):
        edt_cookie[j+23] = expire_date_leak_bytes[j] ^ keystream[j+23]

    new_cookie_long = bytes_to_long(bytes(edt_cookie))
    r = s.get(f"{url}/flag", params={"nonce": nonce, "cookie": new_cookie_long})
    if r.text != "You have expired!":
        print(f"Flag: {r.text}")
        break
```

### 2. Second Solution (Brute Force)
Since the expiration date is randomly generated within a certain range, brute-forcing multiple logins until the flag is returned is feasible.

#### Steps:
1. Continuously request admin logins and retrieve encrypted cookies.
2. Submit each cookie to the `/flag` endpoint.
3. Stop when the flag is returned.

```python
import requests
while True:
    with requests.session() as session:
        url = 'http://130.192.5.212:6522/login'
        params = {'username': 'ciao', 'admin': '1'}
        response = session.get(url, params=params)
        result = response.json()
        cookie = str(result.get("cookie"))
        nonce = str(result.get("nonce"))
        flag_url = 'http://130.192.5.212:6522/flag'
        params = {'cookie': cookie, 'nonce': nonce}
        response = session.get(flag_url, params=params)
        print(response.text)
        if response.text[0] != "Y":
            break
```

## Flag
```
CRYPTO24{53d0fc86-7b8b-4f61-8057-01cf4ad5d03c}
```

