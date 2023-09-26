from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.forms import ValidationError
from django.contrib.auth.models import PermissionsMixin
from mferp.common.validators import phone_validator
from mferp.mastertableconfig.models import MasterConfig, AbstractTime



# class AbstractTime(models.Model):
#     """For Every Database Table"""

#     created_at = models.DateTimeField("Created Date", auto_now_add=True)
#     updated_at = models.DateTimeField("Updated Date", auto_now=True)

#     class Meta:
#         abstract = True


# class MasterConfig(AbstractTime):
#     label = models.CharField(max_length=100)
#     max_subcategory_level = models.PositiveIntegerField(default=5)
#     parent = models.ForeignKey(
#         "self", on_delete=models.CASCADE, null=True, blank=True, related_name="children"
#     )

#     def save(self, *args, **kwargs):
#         # Check if the category already has the maximum number of subcategories
#         if self.parent:
#             if self.parent.children.count() >= self.parent.max_subcategory_level:
#                 raise ValidationError(
#                     "Maximum number of subcategories reached for this parent category."
#                 )

#         # Check the category's level in the hierarchy
#         category = self
#         level = 0
#         while category.parent:
#             category = category.parent
#             level += 1

#         if level >= self.max_subcategory_level:
#             raise ValidationError(
#                 "Maximum subcategory level reached for this category."
#             )

#         super().save(*args, **kwargs)

#     def __str__(self):
#         return self.label


class MyUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.

        param:
            emai (str): Email ID of user
            password (str): password of user
        return:
            user (MyUserManager): user object
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(email=self.normalize_email(email))

        user.user_type = extra_fields.get("user_type")
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        """
        Creates and saves a superuser with the given email and password.
        param:
            emai (str): Email ID of user
            password (str): password of user
        return:
            user (MyUserManager): user object
        """
        instance = MasterConfig.objects.filter(label="super_user").last()
        user = self.create_user(
            email,
            password=password,
            user_type=instance,
            is_verified=True,
            is_superuser=True,
            is_admin=True,
        )
        user.user_type = instance
        user.is_verified = True
        user.is_superuser = True
        user.is_admin = True
        user.first_name = "super"
        user.last_name = "user"
        user.save(using=self._db)
        return user


class Account(AbstractBaseUser, PermissionsMixin):
    """
    Create Account on Database, Account Model
    """

    email = models.EmailField(
        "Email Address", max_length=255, unique=True, null=False, blank=False
    )
    user_type = models.ForeignKey(
        "mastertableconfig.MasterConfig", on_delete=models.CASCADE, related_name="account_masterconfig", null=True, blank=True
    )
    first_name = models.CharField("First Name", max_length=250, null=False, blank=False)
    last_name = models.CharField("Last Name", max_length=250, null=False, blank=False)
    phone_number = models.CharField(
        validators=[phone_validator], max_length=17, blank=True
    )
    is_verified = models.BooleanField(
        "Verified User", default=False, null=False, blank=False
    )
    is_active = models.BooleanField(default=True, null=False, blank=False)
    is_admin = models.BooleanField(default=False, null=False, blank=False)

    objects = MyUserManager()
    # objects = BaseUserManager()

    USERNAME_FIELD = "email"

    def __str__(self):
        return str(self.email)

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        # Simplest possible answer: All admins are staff
        return self.is_admin
