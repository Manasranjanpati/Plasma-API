from django.shortcuts import render
from .serializers import RegisterSerializer
from .models import User
from rest_framework.response import Response
from rest_framework import viewsets,status
import json
import hashlib
from uuid import uuid4

class RegisterView(viewsets.ViewSet):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def list(self, request):
        serializer = self.serializer_class(self.queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        data = json.loads(json.dumps(request.data))
        print(data)
        if "password" not in data:
            return Response(
                {"message": "password is required field",
                    "status": status.HTTP_400_BAD_REQUEST}
            )
        # salt = uuid4().hex
        # cipher = hashlib.sha256(salt.encode(
        #     'utf-8', 'ignore')+data['Password'].encode('utf-8', 'ignore')).hexdigest()
        # data['Password'] = salt + cipher
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': "Account created successfully", "status": status.HTTP_201_CREATED})
        else:
            return Response(
                {"message": serializer.errors, "status": status.HTTP_400_BAD_REQUEST})

class UserLogin(viewsets.ViewSet):
    def create(self,request):
        data = request.data
        serializer_email_data = RegisterSerializer(User.objects.filter(
            email=data['email']),many=True).data

        serializer_pass_data = RegisterSerializer(User.objects.filter(
            password=data['password']), many=True).data
        try:
            if data['email'] == serializer_email_data[0].pop("email") and data['password'] == serializer_pass_data[0].pop("password"):
                return Response({'message': 'User Login Successfully',"status": status.HTTP_200_OK,'id':serializer_email_data[0].pop("id")})
        except:
            return Response({"message": "User authentication failed","status": status.HTTP_401_UNAUTHORIZED})

class UserLogout(viewsets.ViewSet):
    def create(self,request):
        data = request.data
        serialize_user_id_data = RegisterSerializer(User.objects.filter(
            id=data['id']),many=True).data
        try:
            if data['id'] == serialize_user_id_data[0].pop('id'):
                return Response({"statusCode": 200,"message": "Logged out successfully"})
        except:
            return Response({"message": "you havent logged in or invalid id","status": status.HTTP_400_BAD_REQUEST})
