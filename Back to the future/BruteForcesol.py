import requests  # Import the requests library for making HTTP requests

# Infinite loop to continuously attempt login requests until the flag is retrieved
while True:
    # Create a new session for each attempt
    with requests.session() as session:
        # URL of the login endpoint
        url = 'http://130.192.5.212:6522/login'
        
        # Parameters to request an admin login (attempting to gain admin access)
        params = {'username': 'ciao', 'admin': '1'}
        
        # Send GET request to the login endpoint with the given parameters
        response = session.get(url, params=params)
        
        # Parse the JSON response to extract relevant information
        result = response.json()
        
        # Extract the encrypted cookie and nonce values from the response
        cookie = str(result.get("cookie"))
        nonce = str(result.get("nonce"))
        
        # URL of the flag endpoint (where we check if we obtained admin access)
        flag_url = 'http://130.192.5.212:6522/flag'
        
        # Parameters required for the flag request (using the obtained cookie and nonce)
        params = {'cookie': cookie, 'nonce': nonce}
        
        # Send GET request to the flag endpoint with the extracted credentials
        response = session.get(flag_url, params=params)
        
        # Print the response from the server (either an error message or the flag)
        print(response.text)
        
        # If the response does not start with "Y" (indicating failure), break the loop
        # This means the flag has been retrieved successfully
        if response.text[0] != "Y":
            break  # Exit the loop as the flag has been obtained
