from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import UserSerializer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

@api_view(["POST"])
def login(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    user = None
    error_message = None

    # Check by username
    if username:
        user = User.objects.filter(username=username).first()
        if user is None:
            error_message = 'User not found for username'
        elif not user.check_password(password):
            error_message = 'Invalid password for username'

    # Check by email
    if user is None and email:
        user = User.objects.filter(email=email).first()
        if user is None:
            error_message = 'User not found for email'
        elif not user.check_password(password):
            error_message = 'Invalid password for email'

    if user is None:
        return Response({'error': error_message or 'Invalid username or email'}, status=status.HTTP_404_NOT_FOUND)
    
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(instance=user)
    return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_200_OK)

@api_view(["POST"])
def register(request):
    print(request.data)
    user_serializer = UserSerializer(data=request.data)
    if user_serializer.is_valid():
        user = user_serializer.save()
        user.set_password(user_serializer.validated_data["password"])
        user.save()

        token = Token.objects.create(user=user)
        return Response({'token': token.key, 'user': user_serializer.data}, status=status.HTTP_201_CREATED)
                            
    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile(request):
    print(request.user)
    serializer = UserSerializer(instance=request.user)
    return Response(serializer.data)

