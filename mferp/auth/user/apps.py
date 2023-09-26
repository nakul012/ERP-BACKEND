from django.apps import AppConfig
from django.conf import settings
# from mferp.utils.objutils import ObjWrapper


class UserConfig(AppConfig):
    name = 'mferp.auth.user'

#     app_settings = ObjWrapper(getattr(settings, 'AUTH_CONF', {
# 	'ALLOW_SIGNUP': False,
# 	'USE_SIGNUP_REQUEST': False,
# }))


