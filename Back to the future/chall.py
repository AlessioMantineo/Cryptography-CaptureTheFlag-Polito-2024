from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from random import randint
from secret import flag
from flask import Flask, session, jsonify, request
from flask_session import Session

app = Flask(__name__)
app.secret_key = get_random_bytes(16).hex()
app.config['SESSION_TYPE'] = 'filesystem'
sess = Session()
sess.init_app(app)

"""
Importing necessary libraries for cryptography (ChaCha20), random number generation, 
time management, Flask for the web server, and session management.

app.secret_key is set with a random value to ensure session security.
app.config['SESSION_TYPE'] specifies that sessions will be stored on the filesystem.
"""

def make_cipher():
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce, key, cipher

"""
This function generates a random key and a nonce (unique number) for ChaCha20 encryption 
and returns these along with the configured ChaCha20 cipher.
"""

def sanitize_field(field: str):
    return field \
        .replace(" ", "_") \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")

"""
This function replaces or removes special characters from a string to prevent potential injection attacks.
"""

def parse_cookie(cookie: str) -> dict:
    parsed = {}
    for field in cookie.split("&"):
        key, value = field.split("=")
        key = sanitize_field(key)
        value = sanitize_field(value)
        parsed[key] = value

    return parsed

"""
This function converts a cookie string (formatted as key=value&key=value&...) into a dictionary, 
sanitizing both keys and values.
"""

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username")
    admin = int(request.args.get("admin"))

    nonce, key, cipher = make_cipher()
    session['key'] = key

    username = sanitize_field(username)
    
    if admin != 1:
        admin = 0
    else:
        session['admin_expire_date'] = int(time.time()) - randint(10, 266) * 24 * 60 * 60
    expire_date = int(time.time()) + 30 * 24 * 60 * 60
    cookie = f"username={username}&expires={expire_date}&admin={admin}"

    return jsonify({
        "nonce": bytes_to_long(nonce), 
        "cookie": bytes_to_long(cipher.encrypt(cookie.encode()))
    })

"""
Receives two GET parameters: username and admin.
Generates a nonce, a key, and a cipher using make_cipher().
Stores the key in the session.
Sanitizes the username.
If admin is not equal to 1, it is set to 0. If it is 1, a random past expiration date is generated.
Sets an expiration date for the cookie 30 days in the future.
Creates an encrypted cookie using ChaCha20 containing username, expires, and admin fields.
Returns the nonce and the encrypted cookie in JSON format.
"""

@app.route("/flag", methods=["GET"])
def get_flag():
    nonce = int(request.args.get("nonce"))
    cookie = int(request.args.get("cookie"))

    cipher = ChaCha20.new(nonce=long_to_bytes(nonce), key=session['key'])

    try:
        dec_cookie = cipher.decrypt(long_to_bytes(cookie)).decode()
        token = parse_cookie(dec_cookie)
        
        if int(token["admin"]) != 1:
            return "You are not an admin!"
        
        if 290 * 24 * 60 * 60 < abs(int(token["expires"]) - session['admin_expire_date']) < 300 * 24 * 60 * 60:
            return f"OK! Your flag: {flag}"
        else:
            return "You have expired!"
    except:
        return "Something didn't work :C"

"""
Receives two GET parameters: nonce and cookie.
Decrypts the cookie using the nonce and the key stored in the session.
Converts the decrypted cookie into a dictionary.
Checks if the admin field is equal to 1.
Checks if the difference between the cookie expiration date and admin_expire_date 
is between 290 and 300 days.
If both conditions are met, returns the flag. Otherwise, returns an error message.
"""
