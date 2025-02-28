import requests
import time
import random
from Crypto.Util.number import long_to_bytes, bytes_to_long
#http://130.192.5.212: 6522
url = "http://130.192.5.212:6522"
username = "al3m3"

'''
expire_date = int(time.time()) + 30 * 24 * 60 * 60
admin_expire_date_min = int(time.time()) - 12 * 24 * 60 * 60
admin_expire_date_max = int(time.time()) - 265 * 24 * 60 * 60

diff_with_min = abs(expire_date - admin_expire_date_min)
print(f"diff with min: {diff_with_min}")
diff_with_max = abs(expire_date - admin_expire_date_max)
print(f"diff with max: {diff_with_max}")
min_expire_date = 290 * 24 * 60 * 60
max_expire_date = 300 * 24 * 60 * 60

print(int(time.time()))
print(290 * 24 * 60 * 60 < abs(expire_date - admin_expire_date_min) < 300 * 24 * 60 * 60)
print(290 * 24 * 60 * 60 < abs(expire_date - admin_expire_date_max) < 300 * 24 * 60 * 60)

new_time = int(time.time()) + 30 * 24 * 60 * 60
new_time_byte = str(new_time).encode()
'''

s = requests.Session()

r = s.get(f"{url}/login", params = {"username": username, "admin": "1"}).json()
cookie = r["cookie"]
nonce = r["nonce"]

print(f"cookie: {cookie}")
print(f"nonce: {nonce}")

cookie_bytes = long_to_bytes(cookie)
nonce_bytes = long_to_bytes(nonce)

expire_date = int(time.time()) + 30 * 24 * 60 * 60
print(f"first date: {expire_date}")
c = f"username={username}&expires={expire_date}&admin=1".encode()

keystream = bytes([a ^ b for a,b in zip(c, cookie_bytes)])

edt_cookie = bytearray(cookie_bytes)
for i in range(10, 266):
    x = random.randint(290 * 24 * 60 * 60 + int(time.time()) - i * 24 * 60 * 60, 300 * 24 * 60 * 60 + (int(time.time()) - i * 24 * 60 * 60))
    print(f"x: {x}")
    expire_date_leak_bytes = str(x).encode()

    for j in range(10):
        edt_cookie[j+23] = expire_date_leak_bytes[j] ^ keystream[j+23]


    new_cookie_long = bytes_to_long(bytes(edt_cookie))

    r = s.get(f"{url}/flag", params = {"nonce": nonce, "cookie": new_cookie_long})
    if r.text != "You have expired!":
        print(f"flag: {r.text}")
        break