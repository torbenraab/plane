# Python imports
import os
from datetime import datetime
from urllib.parse import urlencode
from base64 import b64encode

import pytz
import requests
import logging

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AuthenticationException,
    AUTHENTICATION_ERROR_CODES,
)


class OpenIDConnectProvider(OauthAdapter):

    provider = "oidc"
    scope = "openid profile email offline_access"

    def __init__(self, request, code=None, state=None, callback=None):

        OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_URL_AUTHORIZATION, OIDC_URL_TOKEN, OIDC_URL_USERINFO = get_configuration_value(
            [
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_URL_AUTHORIZATION",
                    "default": os.environ.get("OIDC_URL_AUTHORIZATION"),
                },
                {
                    "key": "OIDC_URL_TOKEN",
                    "default": os.environ.get("OIDC_URL_TOKEN"),
                },
                {
                    "key": "OIDC_URL_USERINFO",
                    "default": os.environ.get("OIDC_URL_USERINFO"),
                }
            ]
        )

        WEB_URL = get_configuration_value([{
            "key": "WEB_URL",
            "default": os.environ.get("WEB_URL"),
        }])

        OIDC_IDP_CA_CERT = get_configuration_value([{
            "key": "OIDC_IDP_CA_CERT",
            "default": os.environ.get("OIDC_IDP_CA_CERT"),
        }])

        self.idp_ca_cert = OIDC_IDP_CA_CERT[0]
        self.token_url = OIDC_URL_TOKEN
        self.userinfo_url = OIDC_URL_USERINFO

        if not (OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_URL_AUTHORIZATION and OIDC_URL_TOKEN and OIDC_URL_USERINFO):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET
        is_secure = WEB_URL[0].startswith("https")
        redirect_uri = f"""{"https" if is_secure else "http"}://{request.get_host()}/auth/oidc/callback/"""
        url_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "response_type": "code"
        }
        auth_url = (
            f"{OIDC_URL_AUTHORIZATION}?{urlencode(url_params)}"
        )
        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "code": self.code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        basic_auth = b64encode(f"{self.client_id}:{self.client_secret}".encode('utf-8')).decode("ascii")
        headers = {
            "Accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic_auth}",
        }
        token_response = self.get_user_token(
            data=data, headers=headers
        )
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.fromtimestamp(
                        token_response.get("expires_in"),
                        tz=pytz.utc,
                    )
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.fromtimestamp(
                        token_response.get("refresh_token_expired_at"),
                        tz=pytz.utc,
                    )
                    if token_response.get("refresh_token_expired_at")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    def get_user_token(self, data, headers=None):
        try:
            headers = headers or {}
            response = requests.post(
                    self.get_token_url(), data=data, headers=headers, verify=self.idp_ca_cert
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as ex:
            logger = logging.getLogger("plane")
            logger.error("Error getting token from oidc auth provider: {}".format(ex))
            code = self.authentication_error_code()
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES[code],
                error_message=str(code),
            )


    def get_user_response(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.token_data.get('access_token')}"
            }
            response = requests.get(self.get_user_info_url(), headers=headers,  verify=self.idp_ca_cert)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as ex:
            logger = logging.getLogger("plane")
            logger.error("Error getting user info from oidc auth provider: {}".format(ex))
            code = self.authentication_error_code()
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES[code],
                error_message=str(code),
            )


    def set_user_data(self):
        user_info_response = self.get_user_response()
        email = user_info_response.get("email")
        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": user_info_response.get("sub"),
                    "email": email,
                    "avatar": user_info_response.get("avatar_url", ""),
                    "first_name": user_info_response.get("name", ""),
                    "last_name": user_info_response.get("family_name", ""),
                    "is_password_autoset": True,
                },
            }
        )
