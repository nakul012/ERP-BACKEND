import base64
from django.utils.timezone import now, timedelta
from oauth2_provider.settings import oauth2_settings
from oauthlib.common import generate_token
from oauth2_provider.models import Application, AccessToken, RefreshToken
from mferp.common.errors import UserErrors, ClientErrors
from django.utils import timezone

def get_access_token(user: object):
    """ Use function for generate Oauth token for every account on SignUp or Login"""
    try:
        app = Application.objects.get(user=user)
    except Application.DoesNotExist:
        app = Application.objects.create(user=user)
    try:
        token = generate_token()
        refresh_token = generate_token()
        expires = now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        access_token = AccessToken.objects.create(
            user=user, application=app, expires=expires, token=token, scope="read write"
        )
        RefreshToken.objects.create(
            user=user, application=app, token=refresh_token, access_token=access_token
        )
        response = {
            "access_token": access_token.token,
            "expires_in": oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            "token_type": "Bearer",
            "refresh_token": access_token.refresh_token.token,
            "client_id": app.client_id,
            "client_secret": app.client_secret,
        }
        return response
    except Exception as error:
        return error

def encode_token(token:str)->str:
    """
    Encode Access token of user
    Args:
        token (str): Access Token
    Raises:
        Exception: If token format is not correct
    Returns:
        str: encoded string of token
    """
    try:
        message_bytes = token.encode("ascii")
        base64_bytes = base64.b64encode(message_bytes)
        enc_token = base64_bytes.decode("ascii")
        return enc_token
    except:
        raise Exception("Token Not generated")

def decode_token(key_code:str)->str:
    """
    Decode Access token of user
    Args:
        key_code (str): encoded string of token
    Raises:
        Exception: If encoded token format is not correct
    Returns:
        str: Access Token
    """
    try:
        check_token = key_code.isalnum()
        if not check_token:
            raise ClientErrors(
                message="Please Use Valid URL Link", response_code=404
            )

        base64_bytes = key_code.encode("ascii")
        message_bytes = base64.b64decode(base64_bytes)
        token = message_bytes.decode("ascii")
        user = AccessToken.objects.filter(token=token).first().user
        if not user:
            raise ClientErrors(
                message="User not found", response_code=404
            )
        return user
    except UserErrors:
        raise 
    except:
        raise Exception("Token is not correct, Please Use Valid URL Link")


def is_token_expired(token:str)->str:

    try:
        access_token_obj = AccessToken.objects.get(token=token)
        expires_time = access_token_obj.expires
        current_time = timezone.now()
        if current_time >= expires_time:
            return False
        else:
            return True  

    except AccessToken.DoesNotExist:
        return False  
