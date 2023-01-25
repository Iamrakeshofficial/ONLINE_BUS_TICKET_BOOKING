from django.urls import path
from . import views
urlpatterns=[
    path('carousel/', views.carousel, name='car'),
    path('home/',views.home,name='home'),
    path('signup/', views.User_SignUp, name='signup'),
    path('login/', views.User_Login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('password/', views.Password_Change, name='password'),
    path('about/',views.About,name='about'),
    path('contact/', views.Contact1, name='contact'),
    path('buslist/',views.buslist,name='buslist'),
    path('customer/<str:bus>', views.customer, name='customer'),
    path('confirm/', views.confirm, name='confirm'),
    path('payment/',views.Bus_Payment,name='payment'),
    path('pay_status/',views.Payment_Status,name='pay'),
    path('history/',views.History,name='history'),
    path('cus_history/',views.cus_history,name='cus_history'),
    path('thanks/',views.Thanks,name='thanks'),
    path('destination/', views.destination, name='destination'),
    path('busdetais/', views.Busdetais, name='busdetais'),
    path('success/', views.success, name='success'),
    path('delete/',views.delete_user,name='delete'),
    path("get-details/",views.UserDetailAPI.as_view()),
    path('register/',views.RegisterUserAPIView.as_view()),
    path('login1/', views.LoginView.as_view()),
    # path('logout1/', views.LogoutView.as_view()),
    path('bus/', views.BusDetailsView.as_view()),
    path('cont/', views.ContactView.as_view()),
    path('roots/', views.RootView.as_view()),
    path('dest/',views.DestinationView.as_view()),
    path('ticket_history/', views.TicketHistoryView.as_view()),
    path('cus/', views.CustomerView.as_view()),
    path('about1/', views.AboutView.as_view()),
    path('pass/',views.ChangePasswordView.as_view()),
    path('busfilter/',views.BusFilter.as_view()),

    path('activate/<uidb64>/<token>', views.activate, name='activate')

    # path('bookings/', views.bookings, name="bookings"),

]