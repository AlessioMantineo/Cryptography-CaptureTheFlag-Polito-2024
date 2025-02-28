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
        params = {'cookie': cookie,'nonce': nonce}
        response = session.get(flag_url, params=params)
        print(response.text)
        if response.text[0] != "Y":
            break

#CRYPTO24{53d0fc86-7b8b-4f61-8057-01cf4ad5d03c}