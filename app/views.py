from django.shortcuts import render, HttpResponseRedirect,HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import SignUpForm,DestinationForm,BusDetailsForm
from django.contrib import messages
from django.db.models import Q

from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str
from .tokens import account_activation_token


from django.contrib.auth.forms import AuthenticationForm,PasswordChangeForm
from django.contrib.auth import authenticate, login, logout,update_session_auth_hash,get_user_model
from django.core.mail import send_mail,EmailMessage
from .forms import ContactForm,RouteForm, CustomerForm,PaymentForm,Ticket_historyForm,EditUserProfileForm
from django.core.paginator import Paginator
from .models import about, Route, BusDetails, Destination, Customer,Payment,Ticket_history,Profile,Contact
import razorpay
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

#Rest Framework
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import BusDetailsSerializer,ContactSerializer,AddBusDetailsSerializer,UserSerializer,RegisterSerializer,RootSerializer,DestinationSerializer,TicketHistorySerializer,CustomerSerializer,AboutSerializer,ChangePasswordSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import generics
from rest_framework import status
from rest_framework.generics import UpdateAPIView
from rest_framework.authtoken.models import Token





# Create your views here.

class UserDetailAPI(APIView):
  # authentication_classes = (TokenAuthentication,)
  # permission_classes = (AllowAny,)
  def get(self,request,*args,**kwargs):
    user = User.objects.all()
    serializer = UserSerializer(user,many=True)
    return Response(serializer.data)


class RegisterUserAPIView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer


# class LoginView(APIView):
#     # This view should be accessible also for unauthenticated users.
#     permission_classes = (AllowAny,)
#
#     def post(self, request,format=None):
#         serializer = LoginSerializer(data=self.request.data,
#             context={'request': self.request })
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data['user']
#         login(request, user)
#         return Response({'data': {'user': user},
#                     'is_superuser': user.is_superuser,
#                     'is_staff': user.is_staff,'msg': 'Logged in Successfully'}, status=status.HTTP_202_ACCEPTED)

class LoginView(APIView):
    def post(self, request):
        print(request.data)
        username = request.data.get('username')
        password = request.data.get('password')
        print(request.user)
        user = User.objects.filter(username=username).first()
        user.set_password(password)
        if user is not None:
            if user.check_password(password):
                login(request, user)
                print(request.user)
                return Response({
                    'status': 'success',
                    'data': {'user': username},
                    'is_superuser': user.is_superuser,
                    'is_staff': user.is_staff,
                    'message': 'login successful'
                })
            else:
                raise AuthenticationFailed('Incorrect Password')
        else:
            raise AuthenticationFailed('user not found')


# class UpdatePassword(APIView):
#     """
#     An endpoint for changing password.
#     """
#     permission_classes = (IsAuthenticated, )
#
#     def get_object(self, queryset=None):
#         return self.request.user
#
#     def put(self, request, *args, **kwargs):
#         self.object = self.get_object()
#         serializer = ChangePasswordSerializer(data=request.data)
#
#         if serializer.is_valid():
#             # Check old password
#             old_password = serializer.data.get("old_password")
#
#             if not self.object.check_password(old_password):
#                 return Response({"old_password": ["Wrong password."]},
#                                 status=status.HTTP_400_BAD_REQUEST)
#
#             # set_password also hashes the password that the user will get
#             self.object.set_password(serializer.data.get("new_password"))
#             self.object.save()
#             return Response({'msg': 'Password Changed  Successfully'},status=status.HTTP_201_CREATED)
#
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(UpdateAPIView):
    serializer_class = ChangePasswordSerializer

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        # # if using drf authtoken, create a new token
        # if hasattr(user, 'auth_token'):
        #     user.auth_token.delete()
        # token, created = Token.objects.get_or_create(user=user)
        # # return new token
        return Response({'msg': "Password Changed Successfully"}, status=status.HTTP_200_OK)

class BusDetailsView(APIView):
    # def get(self, request, pk=None, format=None):
    #     id = pk
    #     if id is not None:
    #         obj = BusDetails.objects.get(id=id)
    #         serializer = BusDetailsSerializer(obj)
    #         print(serializer)
    #         return Response(serializer.data)
    #     obj = BusDetails.objects.all()
    #     serializer = BusDetailsSerializer(obj, many=True)
    #     return Response(serializer.data)

    # def get(self,request,*args,**kwargs):
    #     print(request.GET)
    #     ori = request.data.get('origin')
    #     des = request.data.get('destination_two')
    #     print(des)
    #     origin = Destination.objects.get(destination=ori)
    #     print(origin,'==========')
    #     destination = Destination.objects.get(destination=des)
    #     obj = BusDetails.objects.filter(Q(source=origin) & Q(destination_one=destination))
    #     # obj=BusDetails.objects.all()
    #     print(obj)
    #     serializer = BusDetailsSerializer(obj, many=True)
    #     return Response(serializer.data)



    def get(self, request, pk=None, format=None):
        id = pk
        print(request.data)
        ori = request.data.get('origin')
        des = request.data.get('destination_two')
        print(des)
        origin = Destination.objects.get(destination=ori)
        print(origin,'==========')
        destination = Destination.objects.get(destination=des)
        print(origin,destination,'-------------------')
        if id is not None:
            obj = BusDetails.objects.get(id=id)
            serializer = BusDetailsSerializer(obj)
            print(serializer)
            return Response(serializer.data)
        # obj = BusDetails.objects.all()
        obj = BusDetails.objects.filter(Q(source=origin) & Q(destination_one=destination))
        serializer = BusDetailsSerializer(obj, many=True)
        return Response(serializer.data)


    def post(self, request, format=None):
        print(request.data)
        serializer = AddBusDetailsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusFilter(APIView):

    def post(self,request,format=None):
        print(request.GET)
        ori = request.data.get('origin')
        des = request.data.get('destination_two')
        print(des)
        origin = Destination.objects.get(destination=ori)
        print(origin, '==========')
        destination = Destination.objects.get(destination=des)
        obj = BusDetails.objects.filter(Q(source=origin) & Q(destination_one=destination))
        # obj=BusDetails.objects.all()
        print(obj)
        serializer = BusDetailsSerializer(obj, many=True)
        return Response(serializer.data)


# class LogoutView(APIView):
#     def get(self, request, format=None):
#         # simply delete the token to force a login
#         request.user.auth_token.delete()
#         return Response(status=status.HTTP_200_OK)

class ContactView(APIView):
    def get(self,request):
        print(type(Contact))
        obj=Contact.objects.all()
        print(obj)
        serializer = ContactSerializer(obj, many=True)
        return Response(serializer.data)

    def post(self,request,format=None):
        print(request.data)
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RootView(APIView):
    def get(self,request):
        print(request,"GET")
        obj=Route.objects.all()
        serializer=RootSerializer(obj,many=True)
        return Response(serializer.data)


    def post(self,request,format=None):
        print(request.data,"POST")

        serializer = RootSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DestinationView(APIView):
    def get(self,request):
        obj=Destination.objects.all()
        serializer=DestinationSerializer(obj,many=True)
        return Response(serializer.data)

    def post(self,request,format=None):
        print(request.data)
        serializer =DestinationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TicketHistoryView(APIView):
    def get(self,request):
        obj=Ticket_history.objects.all()
        serializer=DestinationSerializer(obj,many=True)
        print(serializer.data)
        return Response(serializer.data)

    def post(self,request,format=None):
        print(request.data)
        serializer =TicketHistorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomerView(APIView):
    def get(self,request):
        obj=Customer.objects.all()
        serializer=CustomerSerializer(obj,many=True)
        return Response(serializer.data)

    def post(self,request,format=None):
        print(request.data)
        serializer =CustomerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AboutView(APIView):
    def get(self,request):
        obj=about.objects.all()
        serializer=AboutSerializer(obj,many=True)
        return Response(serializer.data)

    def post(self,request,format=None):
        print(request.data)
        serializer =AboutSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'data created Successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def carousel(request):
    return render(request,'carousel.html')

def update_user_data(user):
    Profile.objects.get_or_create(user=user, defaults={'phone_no': user.profile.phone_no})

# @login_required(login_url='login')
def home(request):
    if request.method == 'POST':
        fm = RouteForm(request.POST)
        if fm.is_valid():
            fm.save()
            request.session['route'] = request.POST
            print(request.POST['destination_two'], '88888888')
            dest = Destination.objects.get(id=request.POST['destination_two'])
            print(dest)
            request.session['dest'] = dest.destination
            return HttpResponseRedirect('/home/buslist/')
        else:
            return render(request,'home.html',{'form':fm})
    else:
        fm = RouteForm()
    return render(request, 'home.html', {'form': fm})



def buslist(request):
   # print(request.session['route'])
    destination = request.session['route']['destination_two']
    origin=request.session['route']['origin']
    print(origin,destination,'/////////////')
    buses = BusDetails.objects.all()
    # for i in buses:
    #     rem=(i.rem)
    #     print(i.source,'sourceeeee')
    #

    if request.method == "POST":
        return HttpResponseRedirect('/home/customer/')
    print(destination,'.......................... using route session')
    return render(request, 'buslist.html', {'buses': buses, 'destination': int(destination),'origin':int(origin)})

def customer(request, bus):
    request.session['customer'] = request.POST
    request.session['bus'] = bus
    busd = BusDetails.objects.filter(bus_name=bus).first()
    busdd= BusDetails.objects.all()
    print(request.session['customer'],'customer session')
    for i in busdd:
        rem = i.rem
        print(rem)
    a = request.session['customer']

    print(a)
    
        

    
    if request.method == 'POST':
        # fm = CustomerForm(request.POST)
        # if fm.is_valid():
        #     fm.save()
        #     fm = CustomerForm()
        print(request.POST)
        customer_details = Customer(name=request.POST['name'], age=request.POST['age'], no_tkt=request.POST['no_tkt'],
                                    bus_name=request.POST['bus'])
        customer_details.save()
        request.session['price'] = busd.price*int(request.POST['no_tkt'])
        print(request.session['price'],'-------------------')
        return HttpResponseRedirect('/home/confirm/')
    else:
        fm = CustomerForm()
    print(request.session['customer'],'customer session')
    return render(request, 'customer.html',{'form':fm, 'bus': bus})


def confirm(request):
    cust = request.session['customer']
    print(request.session['bus'])
    bus = BusDetails.objects.get(bus_name=request.session['bus'], destination_one=request.session['route']['destination_two'])
    # price = bus.price
    price = request.session['price'] 
    print(price,'price')
    print(bus)
    return render(request, 'confirm.html', {'cust': cust, 'bus':bus, 'price':price})


def About(request):
    Post = about.objects.all().order_by('id')
    paginator = Paginator(Post,1,orphans=1)
    page_number = request.GET.get('page')
    page_obj=paginator.get_page(page_number)
    return render(request,'about.html',{'page_obj':page_obj})


def Contact1(request):
    if request.method=='POST':
        fm=ContactForm(request.POST)
        if fm.is_valid():
            fm.save()
            print("Form is Validated")
            return HttpResponseRedirect('/home/thanks')

    else:
        fm=ContactForm()
    return render(request,'contact.html',{"form":fm})


def profile(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            fm = EditUserProfileForm(request.POST, instance=request.user)
            if fm.is_valid():
                messages.success(request, 'Profile Updated !!!')
                fm.save()
        else:
            fm = EditUserProfileForm(instance=request.user)
        return render(request, 'profile.html', {'name': request.user, 'form':fm})
    else:
        return HttpResponseRedirect('/home/login')


def delete_user(request):
    if request.user.is_authenticated:
        user = request.user
        user.is_active = False
        user.save()
        return render(request,'deactive.html')

    else:
        return HttpResponseRedirect('/home/login/')
        

def Password_Change(request):
    if request.user.is_authenticated:
        if request.method=='POST':
            fm=PasswordChangeForm(user=request.user,data=request.POST)
            if fm.is_valid():
                fm.save()
                update_session_auth_hash(request,fm.user)
                messages.success(request,"Successfully Changed the Password")
                HttpResponseRedirect('/home/pro/')

        else:
            fm=PasswordChangeForm(user=request.user)
        return render(request,'passwordchange.html',{"form":fm})

    else:
        HttpResponseRedirect('/home/login/')


# def User_SignUp(request):
#     if request.method == 'POST':
#         fm= SignUpForm(request.POST)
#         if fm.is_valid():
#             user = fm.save()
#             # user.refresh_from_db()
#             #newly added
#             profile=Profile(user_id=user.id)
#             profile.phone_no = fm.cleaned_data.get('phone_no')
#             profile.save()
#
#             # if  fm.cleaned_data.get('flag') == False:
#             #     user.is_active = False
#
#             # load the profile instance created by the signal
#             fm.save()
#             # user=fm.save(commit=False)
#             # user.is_active=False
#             # user.save()
#             Email = fm.cleaned_data['email']
#             messages.success(request, 'Successfully Registered')
#             send_mail(' Registration Successfull',
#                       'Signup and Registration Was Successfull Congratulations Now You can read and Write Blogs On My Website.',
#                       'iamrakeshofficial143@gmail.com', [str(Email)], fail_silently=False)
#             print("Form is Validated...")
#             print("Email sent was SuccessFull...")
#             return HttpResponseRedirect('/home/login')


            #
            # current_site = get_current_site(request)
            # mail_subject = 'Activation link has been sent to your email id'
            # message = render_to_string('active_email.html', {
            #     'user': user,
            #     'domain': current_site.domain,
            #     'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            #     'token': account_activation_token.make_token(user),
            # })
            # to_email = fm.cleaned_data.get('email')
            # email = EmailMessage(
            #     mail_subject, message, to=[to_email]
            # )
            # email.send()
            # return HttpResponse('Please confirm your email address to complete the registration')
            #

    # else:
    #     fm = SignUpForm()
    # return render(request, 'signup.html', {"form": fm})


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('<h1>Thank you for your email confirmation. Now you can login your account.<h1>')
    else:
        return HttpResponse('Activation link is invalid!')

def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    message = render_to_string("active_email.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')

def User_SignUp(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active=False
            # profile = Profile(user_id=user.id)
            # profile.phone_no = form.cleaned_data.get('phone_no')
            # profile.save()
            user.save()
            activateEmail(request, user, form.cleaned_data.get('email'))
            return HttpResponseRedirect('/home/home')

        else:
            for error in list(form.errors.values()):
                messages.error(request, error)

    else:
        form = SignUpForm()

    return render(
        request=request,
        template_name="signup.html",
        context={"form": form}
        )

def User_Login(request):
    print(request.user)
    if not request.user.is_authenticated:
        if request.method == "POST":
            fm = AuthenticationForm(request=request, data=request.POST)
            if fm.is_valid():
                un = fm.cleaned_data['username']
                up = fm.cleaned_data['password']
                user = authenticate(username=un, password=up)

                if user is not None:
                    login(request, user)
                    messages.success(request, 'Logged in Successfully')

                    return HttpResponseRedirect('/home/home')

        else:
            fm = AuthenticationForm()
        return render(request, 'login.html', {"form": fm})
    else:
        return HttpResponseRedirect('/home/profile')



def user_logout(request):
    if request.method == 'POST':
        logout(request)
        return HttpResponseRedirect('/home/login/')
    return render(request, 'logout.html')


@csrf_exempt
def Bus_Payment(request):
    amount = request.session['price']
    if request.method == 'POST':
        # Create Razorpay Client Here
        client = razorpay.Client(auth=('rzp_test_wCUhmovnGlyfuz', 'pkpcgsmyKzbFY4uXmpO3POmn'))
        # Create Order Here

        name = request.session['customer']['name']
        response_payment = client.order.create(dict(amount=amount*100, currency='INR'))
        order_id = response_payment['id']
        order_status = response_payment['status']

        if order_status == 'created':
            pr = Payment(
                name=name,
                amount=amount,

                order_id=order_id,
                order_status=order_status,
            )
            pr.save()
            response_payment['name'] = name

            form = PaymentForm(request.POST)
            return render(request, 'ticket_payment.html', {'form': form, 'payment': response_payment,'amount':amount})
            # return HttpResponseRedirect('/home/pay_status/')


        # print(response_payment)
    # price = request.session['price']
    # print(price)
    form = PaymentForm()
    return render(request, 'ticket_payment.html', {'form': form, 'amount': amount})


def Payment_Status(request):
    return render(request,'success.html')

@csrf_exempt
def success(request):
    print(request.session,'yessssss')
    route = request.session['route']
    customer = request.session['customer']
    print(route,'-----------------route session')
    print(customer)

    bus_list = BusDetails.objects.all()

    for i in bus_list:
        print(type(route['destination_two']), type(i.destination_one))

        if i.destination_one == route['destination_two']:
            print(i.price)

    Ticket_history(user=request.user, name=customer['name'], bus_name=customer['bus'],
                   aadhar_no=customer['aadhar_no'], origin=route['origin'],
                   date=route['date'],destination=request.session['dest']).save()
    ticket_history = Ticket_history.objects.all()
    for i in ticket_history:
        print(i.aadhar_no,'aadhar number')

    return render(request, 'success.html')

def History(request):
    

    bus_list = BusDetails.objects.all()
    ticket_history = Ticket_history.objects.all()
    for i in ticket_history:
        print(i.bus_name, ',,,,,,,,,,,,,,,,,,,,,,,,,,,,,,')
   


    ticket_history = Ticket_history.objects.all()
    return render(request,'history.html',{'ticket_history':ticket_history})

@login_required(login_url='login')
def cus_history(request):
    if request.user is not None:
        print(request.user,'#########')
        obj = Ticket_history.objects.filter(user=request.user)

        # print(obj,'---------')
        # for i in obj:
        #     print(i.name,'..............')

        return render(request, 'cus_history.html',{'obj':obj})
    else:
        HttpResponse("You Dont have any Bookings.")

def Thanks(request):
    return render(request,'thanks.html')

def destination(request):
    if request.method=='POST':
        fm=DestinationForm(request.POST)
        if fm.is_valid():
            fm.save()
            fm = DestinationForm()
            messages.success(request, '<h2>Logged in Successfully</h2>')

            print("Form is Validated")
            return HttpResponseRedirect('')

    else:
        fm=DestinationForm()
    return render(request,'destination.html',{"form":fm})

def Busdetais(request):
    if request.method=='POST':
        fm=BusDetailsForm(request.POST)
        if fm.is_valid():
            fm.save()
            fm = BusDetailsForm()
            messages.success(request, '<h2>Logged in Successfully</h2>')

            print("Form is Validated")
            return HttpResponseRedirect('/home/home')

    else:
        fm=BusDetailsForm()
    return render(request,'busdetails.html',{"form":fm})





