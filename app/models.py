from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail

from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin


# class CustomAccountManager(BaseUserManager):
#     def create_superuser(self, email, username, first_name, last_name, password, **other_fields):
#         other_fields.setdefault('is_staff', True)
#         other_fields.setdefault('is_superuser', True)
#         other_fields.setdefault('is_active', True)
#         if other_fields.get("is_staff") is not True:
#             raise ValueError("Super user must be assigned to is_staff=True.")
#         if other_fields.get("is_active") is not True:
#             raise ValueError("Super user must be assigned to is_staff=True.")
#         if other_fields.get("is_superuser") is not True:
#             raise ValueError("Superuser must be assigned is_superuser =True.")
#         return self.create_user(email, username, first_name, last_name, password, **other_fields)
#
#
#     def create_user(self, email, username, first_name, last_name, password, **other_fields):
#        if not email:
#            raise ValueError(_("You must provide an email address"))
#        other_fields.setdefault('is_active', True)
#        if other_fields.get("is_active") is not True:
#             raise ValueError("Super user must be assigned to is_staff=True.")
#
#        email = self.normalize_email(email)
#        user = self.model(email=email, username=username, first_name=first_name, last_name=last_name, **other_fields)
#        user.set_password(password)
#        user.save()
#        return user
# class NewUser(AbstractBaseUser, PermissionsMixin):
#     user_id = models.BigAutoField(primary_key=True)
#     email = models.EmailField(_("email address"), unique=True)
#     username = models.CharField(max_length=150, unique=True)
#     first_name = models.CharField(max_length=150, blank=True)
#     last_name = models.CharField(max_length=150, blank=True)
#     mobile_number = models.IntegerField()
#     start_date = models.DateTimeField(default=timezone.now)
#     is_staff = models.BooleanField(default=False)
#     is_active = models.BooleanField(default=True)
#
#
#     objects = CustomAccountManager()
#     USERNAME_FIELD = 'username'
#     REQUIRED_FIELDS = ['email', 'first_name', 'last_name', 'mobile_number']
#
#     def __str__(self) -> str:
#         return self.username



class Profile(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    phone_no=models.CharField(max_length=13,null=True)

    def __str__(self):
        return self.phone_no

# GENDER_SELECTION = [
#     ('M', 'Male'),
#     ('F', 'Female'),
#     ('NS', 'Not Specified'),
# ]
# class CustomUser(AbstractUser):
#     # We don't need to define the email attribute because is inherited from AbstractUser
#     gender = models.CharField(max_length=20, choices=GENDER_SELECTION)
#     phone_number = models.CharField(max_length=30)
#

class Contact(models.Model):
    name = models.CharField(max_length=20,default="Akash")
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message =models.CharField(max_length=500)
    bus_name = models.CharField(max_length=20)
    origin = models.CharField(max_length=10)
    destination = models.CharField(max_length=10)
    bus_No = models.CharField(max_length=50)
    driver_phono = models.IntegerField()

class about(models.Model):
    bus_name=models.CharField(max_length=200,null=True)
    travels=models.TextField(max_length=5000,null=True)



class Destination(models.Model):
    destination = models.CharField(max_length=200)

    def __str__(self):
        return self.destination


class BusDetails(models.Model):
    source = models.ForeignKey(Destination, on_delete=models.CASCADE,related_name='source_loc')
    destination_one = models.ForeignKey(Destination, on_delete=models.CASCADE,related_name='dest_loc')
    bus_name = models.CharField(max_length=200)
    vehicle_num = models.CharField(max_length=200)
    driver_no = models.CharField(max_length=200)
    start_time = models.TimeField()
    arrival_time=models.TimeField()
    price = models.IntegerField()
    nos = models.DecimalField(decimal_places=0, max_digits=2,default=60)
    rem = models.DecimalField(decimal_places=0, max_digits=2)
    bus_type=models.CharField(max_length=10)

    def __str__(self):
        return str(self.bus_name)


class Route(models.Model):
    origin = models.ForeignKey(Destination, on_delete=models.CASCADE, related_name='Origin_location',error_messages={'origin':'Enter Your Origin'})
    destination_two = models.ForeignKey(Destination, on_delete=models.CASCADE, related_name='destination_location',error_messages={'destination_two':'Enter Your Destination'})
    date = models.DateField()

    def __str__(self):
        return str(self.destination_two)


s = (('Male',"Male"),('Female','Female'),('Other','Other'))
class Customer(models.Model):
    name = models.CharField(max_length=200, null=True)
    age = models.IntegerField(null=True)
    sex = models.CharField(max_length=200, choices=s)
    aadhar_no = models.IntegerField(null=True)
    bus_name = models.CharField(max_length=100, null=True)
    no_tkt=models.IntegerField(default='1')

    def __str__(self):
        return str(self.bus_name)


class Payment(models.Model):
    name = models.CharField(max_length=50, null=False)
    amount = models.IntegerField(default=0)
    order_id = models.CharField(max_length=100, blank=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True)
    paid = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class Ticket_history(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=20,null=True)
    bus_name = models.CharField(max_length=200)
    aadhar_no = models.IntegerField(null=True)
    origin = models.CharField(max_length=100 )
    destination = models.CharField(max_length=200)
  #  price = models.IntegerField()
    date = models.DateField()
   # start_time = models.TimeField()
   # arrival_time=models.TimeField()

    def __str__(self):
        return self.user









