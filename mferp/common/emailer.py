from typing import List
from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from mferp.auth.user.models import Account
from oauth2_provider.models import AccessToken


def email_verify(
    subject: str, to: str, link: str, from_email=settings.MAIL_SENDING_USER
):
    """
    Send mail to client user for account verification when any client user signup on EZ secure transfer

    param:
        subject (str): Subject of the mail
        to (str): User's email ID
        link (str): link using which will verify yourself
        from_email (str): email ID used to send the verification mail

    return:

    """
    try:
        # data = {"link": link}
        text_content = 'Hi '+ \
            ' Use the link below to verify your email \n' + link
        # text_content = "This is an important message."
        # email_html = get_template("verify_account.html")
        
        # html_content = email_html.render(data)
        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        # msg.attach_alternative(html_content, "text/html")
        msg.send()
    except:
        raise Exception()
    

def forget_password(
    subject: str, to: str, link: str, from_email=settings.MAIL_SENDING_USER
):
    """
    Send mail to user to the send the verification link when user forgot password and unable to login

    param:
        subject (str): Subject of the mail
        to (str): User's email ID
        link (str): link using which will verify yourself
        from_email (str): email ID used to send the verification mail

    return:

    """
    import datetime
    try:
        user = Account.objects.filter(email=to).last()
        expires_time = AccessToken.objects.filter(user=user).last().expires
        current_time = datetime.datetime.now(datetime.timezone.utc)
        time_diff = ((expires_time - current_time).total_seconds())//3600

        text_content = f'Hi {to}'+ \
            f' Use the link below to reset the password \n This link is valid for {time_diff} hours \n {link}'
        #email_html = get_template("password_reset.html")
        #data = {"link": link}
        #html_content = email_html.render(data)
        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        #msg.attach_alternative(html_content, "text/html")
        msg.send()
    except:
        raise Exception()