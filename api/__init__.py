'''
ISC License

Copyright (c) 2022, Palo Alto Networks Inc.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

import yaml
import os
import jwt
import threading
import logging
import datetime
from jwt import PyJWKClient
from jwt.exceptions import ExpiredSignatureError
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


class PanApiSession(OAuth2Session):
    """PanApi extension to :class:`requests_oauthlib.OAuth2Session`.

    Methods
    -------
    authenticate(self, **kwargs)
        Create the OAuth2 session and request an access token

    validate(self)
        Validate the OAuth2 session's access token

    refresh(self)
        Request a new OAuth2 access token for the session

    decode_token(self)
        Validate the JWT token contents and signature

    Properties
    ----------
    is_expired
        Has the the access token expired?
    """

    _configfile = "~/.panapi/config.yml"

    def authenticate(self, token_url = 'https://auth.apps.paloaltonetworks.com/oauth2/access_token', **kwargs):
        self.token_url = 'https://auth.apps.paloaltonetworks.com/oauth2/access_token'
        # Process the configfile or kwargs
        keys = ("client_id", "client_secret", "tsg_id")
        if set(keys).issubset(kwargs):
            self.client_id = kwargs.get("client_id")
            self.client_secret = kwargs.get("client_secret")
            self.tsg_id = kwargs.get("tsg_id")
        else:
            if "configfile" in kwargs:
                self._configfile = kwargs.get("configfile")
            f = os.path.abspath(
                os.path.expanduser(os.path.expandvars(self._configfile))
            )
            with open(f, "r", encoding="utf-8-sig") as c:
                config = yaml.safe_load(c.read())
            self.client_id = config["client_id"]
            self.client_secret = config["client_secret"]
            self.tsg_id = config["tsg_id"]
        # Fix the scope to include email and profile
        self.scope = "email profile tsg_id:" + str(self.tsg_id)
        # Request the access token and retrieve the issuer's signing key
        oauth2_client = BackendApplicationClient(
            client_id=self.client_id, scope=self.scope
        )
        self._client = oauth2_client
        self.fetch_token(
            token_url=self.token_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        # Retrieve the signing key for token validation
        jwks_uri = (
            "/".join(self.token_url.split("/")[:-1]) + "/connect/jwk_uri"
        )
        jwks_client = PyJWKClient(jwks_uri)
        self.signing_key = jwks_client.get_signing_key_from_jwt(
            self.access_token
        )
        expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.token['expires_in'])
        logging.info(f"Token will expire at {expiry}")
        
        # Calculate and store the expiry time
        self.token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.token['expires_in'])
        logging.info(f"Token will expire at {self.token_expiry}")            

    def reauthenticate(self):
        logging.info("Reauthenticating session...")
        self.fetch_token(
            token_url=self.token_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        # Update the token expiry time after reauthentication
        self.token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.token['expires_in'])
        logging.info(f"New token will expire at {self.token_expiry}")

    def decode_token(self):
        payload = jwt.decode(
            self.access_token,
            self.signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            options={"verify_exp": False, "verify_iat": False},
        )
        return payload

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.Lock()

    def ensure_valid_token(self):
        with self._lock:
            if self.is_expired:
                self.reauthenticate()
    
    @property
    def is_expired(self):
        # Check if current time is within 60 seconds of the token expiry time
        buffer_time = datetime.timedelta(seconds=60)
        if datetime.datetime.utcnow() >= (self.token_expiry - buffer_time):
            logging.info("Token is about to expire or has expired")
            return True
        return False
