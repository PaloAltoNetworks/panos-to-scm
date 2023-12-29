# token_utils.py

import requests
import json
import time
import os
from requests.exceptions import RequestException

def obtain_api_token(client_id, client_secret, tsg_id, token_file, force_refresh=False): ##using token_file argument
    """
    Obtain and return the API token. If force_refresh is False and a valid token is cached, 
    return the cached token. Otherwise, request a new token and cache it.
    """
    if not force_refresh and os.path.exists(token_file):
        with open(token_file, "r") as f:
            token_data = json.load(f)

        if time.time() < token_data["expires_at"]:
            # print("Token is not expired, capturing and storing api token")
            # print(token_data)
            return token_data["access_token"]

    print("Fetching new Token because it's expired or force_refresh is set")

    url = 'https://auth.apps.paloaltonetworks.com/oauth2/access_token'
    payload = {'grant_type': 'client_credentials', 'scope': f'tsg_id:{tsg_id}'}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(url, data=payload, headers=headers, auth=(client_id, client_secret))

    if response.status_code == 200:
        data = json.loads(response.text)
        token = data["access_token"]
        # print(token)
        expires_in = data["expires_in"]

        token_data = {
            "access_token": token,
            "expires_at": time.time() + expires_in - 180  # Subtract 180 seconds to account for potential delays
        }

        with open(token_file, "w") as f:
            json.dump(token_data, f)

        return token
    else:
        raise RequestException(f"Error: {response.status_code} {response.reason}")
