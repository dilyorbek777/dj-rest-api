from django.urls import path
from .views import *


urlpatterns = [
    path('login/', LoginView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyAPIView.as_view()),
    path('new-verify/', getNewVerificationView.as_view()),
    path('change-user/', ChangeUserInformationView.as_view()),
    path('change-photo/', ChangeUserPhotoView.as_view())
]