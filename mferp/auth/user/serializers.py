import base64
from django.forms import ValidationError
import requests
from mferp.auth.user.tokens import decode_token, get_access_token
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from mferp.common.errors import ClientErrors
from .models import MasterConfig, Account
from django.db.models import Q
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from mferp.auth.user.tokens import get_access_token, encode_token
from oauth2_provider.models import AccessToken
from rest_framework import status
from mferp.common.functions import check_password


class UserLoginSerializer(serializers.Serializer):
    """
    Return authenticated user email
    data:
        email and password
    """

    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        email = data["email"]
        password = data["password"]
        acc_obj = Account.objects.filter(email=data["email"])
        if not acc_obj:
            raise ClientErrors(message="Account Not Found", response_code=404)

        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if user.is_active:
                    data["user"] = user
                else:
                    raise ValidationError("User is deactivated")
            else:
                raise ValidationError("Unable to login with given credentials")
        return data


class SignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"

    def create(self, validated_data):
        user = Account.objects.create(**validated_data)
        user.set_password(validated_data["password"])
        user.save()
        return user


class ForgetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, data):
        user = Account.objects.filter(email=data["email"]).last()
        if not user:
            raise ClientErrors(
                message="This email is not registered with us, kindly signup!",
                response_code=404,
            )
        else:
            if user.is_verified:
                if user.is_active:
                    data["user"] = user
                else:
                    raise ValidationError("User is deactivated")
            else:
                raise ValidationError("User is not verified")
        return data


class VerifyAccountSerializer(serializers.Serializer):
    q = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        key_code = data.get("q")
        user = decode_token(key_code)
        token = AccessToken.objects.filter(user=user).last().token
        data["user"] = user
        data["token"] = token
        return data


class ResetPasswordEmailSerializer(serializers.Serializer):
    q = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        key_code = data.get("q", "")
        user = decode_token(key_code)
        data["user"] = user
        return data
