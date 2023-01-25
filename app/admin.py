from django.contrib import admin
from .models import Contact,about,Route,BusDetails, Destination, Customer,Ticket_history,Payment,Profile

# Register your models here.

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ['id','name','email','subject','message','bus_name','origin','destination','bus_No','driver_phono']


@admin.register(about)
class PostAdmin(admin.ModelAdmin):
 list_display = ['bus_name','travels']

@admin.register(Route)
class RouteAdmin(admin.ModelAdmin):
     list_display = ['id', 'origin', 'destination_two', 'date']

@admin.register(BusDetails)
class BusDetailsAdmin(admin.ModelAdmin):
     list_display = ['id', 'source', 'destination_one', 'bus_name', 'vehicle_num', 'driver_no', 'arrival_time','start_time', 'price','nos','rem','bus_type']

@admin.register(Destination)
class DestinationAdmin(admin.ModelAdmin):
     list_display = ['id', 'destination']

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
     list_display = ['name', 'age', 'sex', 'aadhar_no', 'bus_name','no_tkt']

@admin.register(Ticket_history)
class Ticket_historyAdmin(admin.ModelAdmin):
     list_display = ['name', 'bus_name', 'aadhar_no', 'origin', 'destination','date', 'user']


admin.site.register(Profile)
admin.site.register(Payment)