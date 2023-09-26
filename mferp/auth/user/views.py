import base64
from django.http import HttpRequest, HttpResponseRedirect
from django.db.models import Q
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.urls import reverse
import requests
from mferp.common.functions import check_password
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from mferp.auth.user.models import Account, MasterConfig
from mferp.common.errors import ClientErrors, DatabaseErrors, UserErrors
from mferp.auth.user.tokens import get_access_token, encode_token, is_token_expired
from django.conf import settings
from .serializers import (
    ForgetPasswordEmailSerializer,
    VerifyAccountSerializer,
    UserLoginSerializer,
    SignUpSerializer,
    ResetPasswordEmailSerializer,
)
from oauth2_provider.models import AccessToken, RefreshToken
from rest_framework.permissions import IsAuthenticated
from mferp.common.emailer import email_verify, forget_password
from datetime import datetime

BASE_URL = settings.BASE_URL


class UserSignUpView(APIView):
    def post(self, request: HttpRequest) -> Response:
        """
        User SignUp API

        POST:
        Create a new User and return auth token
        """
        try:
            serializer = SignUpSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            if Account.objects.filter(email=request.data["email"]):
                raise ClientErrors(message="Account already exists", response_code=400)
            password_check = check_password(request.data["password"])
            if password_check:
                serializer.save()
                user = Account.objects.last()
                user_token = get_access_token(user=user)
                token = user_token["access_token"]
                enc_token = encode_token(token)
                link = BASE_URL + "/v1/verify-account" + "?q=" + enc_token
                email = request.data["email"]
                try:
                    email_verify("Account Verification Email - ERP 3.0", email, link)
                except:
                    UserErrors(message="Please check your Email ID.", response_code=500)
                return Response(
                    {
                        "message": "Account Created Successfully",
                        "success": True,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                raise Exception(password_check)
        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class UserLoginView(APIView):
    def post(self, request):
        """
        Operation Team Login API

        POST:
        Login Ops user and return new auth token
        """
        try:
            serializer = UserLoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            token = get_access_token(user)
            return Response(
                {
                    "message": "Logged In Successfully",
                    "is_verified": user.is_verified,
                    "token": token,
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class UserLogoutView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]

    def post(self, request: HttpRequest) -> Response:
        """
        Logout API For Ops User

        param:
            usertoken in AUTH PARAMETER
        """
        try:
            user_token = request.auth
            refresh_tokens = RefreshToken.objects.filter(access_token=user_token)
            refresh_tokens.delete()
            user_token.delete()
            return Response(
                {"message": "You are successfully logout", "success": True},
                status=status.HTTP_200_OK,
            )
        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class VerifyAccountView(APIView):
    """
    When user Signup, user have to verify the account first before login
    encoded string of token send on user's mail
    Verify encoded string  API

    In GET: Verify Account
        param:
            q (str): Key code that shared  on user's email ID

        response:
            200:
                description: Verify account user
                message (str): Account Verified Successfully
                success (bool): True
    """

    def get(self, request: HttpRequest) -> Response:
        """Get Email Code And Verify Account"""
        try:
            serializer = VerifyAccountSerializer(data=request.query_params)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            if user.is_verified:
                raise ClientErrors(
                    message="Your Account is Already Verified",
                    error_message=str(user.email),
                    response_code=400,
                )
            else:
                user.is_verified = True
                user.save()
                return Response(
                    {"message": "Account Verified Successfully", "success": True},
                    status=status.HTTP_200_OK,
                )

        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )
        except Exception as error:
            return Response(
                {"message": "Something Went Wrong", "success": False},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ForgetPasswordEmailView(APIView):
    def post(self, request: HttpRequest) -> Response:
        """
        Trigger Email For Client Forget Password API

        param:
            email (str): email of user
        """
        try:
            serializer = ForgetPasswordEmailSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            AccessToken.objects.filter(user=user).delete()
            RefreshToken.objects.filter(user=user).delete()
            token = get_access_token(user)
            token = token["access_token"]
            enc_token = encode_token(token)
            link = BASE_URL + "/v1/forgotpassword-verify/?q=" + str(enc_token)
            email = request.data["email"]
            forget_password("password reset ", email, link)
            return Response(
                {
                    "message": "Account Verification Email Sent Successfully",
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )
        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class ForgetPasswordVerifyView(APIView):
    """
    When user forget password, user have to verify the encoded string of token first before login
    encoded string of token send on user's mail
    Verify encoded string  API

    In GET: Verify token validity
        param:
            q (str): Key code that shared  on user's email ID

        response:
            200:
                description: Verify client user
                message (str): Account Verified Successfully
                success (bool): True
    """

    def get(self, request: HttpRequest) -> Response:
        try:
            serializer = VerifyAccountSerializer(data=request.query_params)
            serializer.is_valid(raise_exception=True)
            key_code = serializer.validated_data.get("token", "")
            if not is_token_expired(key_code):
                raise ClientErrors(
                    message="URL Link is expired. Please apply forget password again",
                    response_code=404,
                )
            # Add redirect code to the reset password template
            # url = reverse('v1/reset-password/')
            # HttpResponseRedirect(url)
            return Response(
                {
                    "message": "Token is valid you can reset your password",
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class ResetPasswordView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request: HttpRequest) -> Response:
        """
        Change Password For Client Side API

        param:
            new_password (str): new password of client user
        """
        try:
            serializer = ResetPasswordEmailSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            password_check = check_password(serializer.validated_data["password"])
            if password_check:
                user.set_password(serializer.validated_data["password"])
                user.save()
                AccessToken.objects.filter(user=user).delete()
                RefreshToken.objects.filter(user=user).delete()
            else:
                raise Exception(password_check)
            return Response(
                {
                    "message": "Password reset successfully",
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )
        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )


class ChangePasswordView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]

    def post(self, request: HttpRequest) -> Response:
        """
        Change Password For Client Side API

        param:
            password (str): old password of client user
            new_password (str): new password of client user
        """
        try:
            if ("old_password" or "new_password") not in request.data:
                raise ClientErrors(message="All fields are required", response_code=400)
            old_password = request.data.get("old_password")
            new_password = request.data.get("new_password")
            password_check = check_password(new_password)
            if password_check:
                user = authenticate(username=request.user.email, password=old_password)
                if user is not None:
                    user = get_object_or_404(Account, id=request.user.id)
                    user.set_password(new_password)
                    user.save()
                    AccessToken.objects.filter(user=user).delete()
                    RefreshToken.objects.filter(user=user).delete()
                    token = get_access_token(user)
                else:
                    raise ClientErrors(
                        message="Current Password Incorrect, Check Again",
                        response_code=400,
                    )
            else:
                raise Exception(password_check)
            return Response(
                {
                    "token": token,
                    "message": "Password reset successfully",
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )
        except UserErrors as error:
            return Response(
                {"message": error.message, "success": False}, status=error.response_code
            )
