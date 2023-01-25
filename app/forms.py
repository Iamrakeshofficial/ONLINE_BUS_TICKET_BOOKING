from django.contrib.auth.models import User
from django import forms
from .models import Route, Customer,Payment,Contact,Ticket_history,Destination,BusDetails
from django.contrib.auth.forms import UserCreationForm,UserChangeForm
from django.contrib.auth.models import User
from django.utils import timezone
from django.core import validators




class SignUpForm(UserCreationForm):
 phone_no = forms.CharField(min_length=10,max_length=13, widget=forms.TextInput)
 password1 = forms.CharField(label='Enter Password', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
 password2 = forms.CharField(label='Confirm Password (again)',widget=forms.PasswordInput(attrs={'class': 'form-control'}))

 # def clean(self):
 #  ph=self.cleaned_data.get('phone_no')
 #  print(self.cleaned_data)
 #  if len(ph) != 10:
 #   raise forms.ValidationError('Enter a Valid Phone Number')


    
 class Meta:
  model = User
  fields = ['username', 'first_name', 'last_name', 'email','phone_no']
  labels = {'email': 'Email','phone_no':'Enter Your Mobile Number'}
  error_messages = {
   'username': {'required': 'Give your name'}}

  

  widgets = {
   'username': forms.TextInput(attrs={'class': 'form-control'}),
   'first_name': forms.TextInput(attrs={'class': 'form-control'}),
   'last_name': forms.TextInput(attrs={'class': 'form-control'}),
   'email': forms.EmailInput(attrs={'class': 'form-control'}),
   'phone_no': forms.TextInput(attrs={'class': 'form-control'}),
  
  }

class EditUserProfileForm(UserChangeForm):
  password=None
  class Meta:
    model=User
    fields=['username', 'first_name', 'last_name', 'email','date_joined','last_login']

class RouteForm(forms.ModelForm):
 date = forms.DateField(widget=forms.NumberInput(attrs={'type': 'date'}))

 def clean(self):
    org=self.cleaned_data.get('origin')
    dest=self.cleaned_data.get('destination_two')
    if org == dest :
      raise forms.ValidationError('Your Origin and Destination Same Please Select Different Origin/Source')

 class Meta:
  model = Route
  fields = ['origin','destination_two','date']
  labels = {'origin':'Enter Your Origin','destination_two':'Enter Your Destination','date':'Date'}

  

  widgets = {
   'date': forms.DateInput(attrs={'class': 'form-control'}),
   }





class CustomerForm(forms.ModelForm):
 class Meta:
  model = Customer
  fields = '__all__'

class Ticket_historyForm(forms.ModelForm):
 class Meta:
  model = Ticket_history
  fields = '__all__'


class CustomerForm(forms.ModelForm):
 class Meta:
  model = Customer
  fields = ['name', 'age','sex','no_tkt']
  labels = {'name': 'Enter Name', 'age': 'Enter Age','sex':'Enter Your Gender','bus_name':'Enter Bus Name','no_tkt':'Enter Ticket Number'}

  widgets = {
   'name': forms.TextInput(attrs={'class': 'form-control'}),
   'age': forms.NumberInput(attrs={'class': 'form-control'}),
   
   'no_tkt': forms.NumberInput(attrs={'class': 'form-control'}),



  }
    

class PaymentForm(forms.ModelForm):
 class Meta:
  model = Payment
  fields = ['name', 'amount']
  label = {'name': 'Enter Name', 'amount': 'Enter Ticket Amount'}

  widgets = {
   'name': forms.TextInput(attrs={'class': 'form-control'}),
   'amount': forms.NumberInput(attrs={'class': 'form-control'}),}


class ContactForm(forms.ModelForm):
 class Meta:
  model = Contact
  fields = ['name', 'email', 'subject', 'message','bus_name','origin','destination','bus_No','driver_phono']
  labels = {'name': 'Enter Your Name', 'email': 'Enter Your EMail', 'subject': 'Enter Subject','bus_name':'Travel name','origin':'Enter Your Origin','destination':'Enter Your Destination','bus_No':'Enter Bus_No','driver_phono':'Enter Driver_phon_no'}
  widgets = {
   'name': forms.TextInput(attrs={'class': 'form-control'}),
   'first_name': forms.TextInput(attrs={'class': 'form-control'}),
   'subject': forms.TextInput(attrs={'class': 'form-control'}),
   'email': forms.EmailInput(attrs={'class': 'form-control'}),
   'message': forms.Textarea(attrs={'class': 'form-control'}),
   'bus_name': forms.TextInput(attrs={'class': 'form-control'}),
   'origin': forms.TextInput(attrs={'class': 'form-control'}),
   'destination': forms.TextInput(attrs={'class': 'form-control'}),
   'bus_No': forms.TextInput(attrs={'class': 'form-control'}),
   'driver_phono': forms.TextInput(attrs={'class': 'form-control'}),


  }

class DestinationForm(forms.ModelForm):
 class Meta:
  model = Destination
  fields = ['destination']
  label = {'destination':'Enter destination' }

  widgets = {
   'destination': forms.TextInput(attrs={'class': 'form-control'})}

class BusDetailsForm(forms.ModelForm):
 class Meta:
  model = BusDetails
  fields = '__all__'
