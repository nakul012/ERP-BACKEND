from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import MasterConfig
from .serializers import MasterConfigSerializer
from rest_framework import generics

class CreateCategoryOrSubcategoryView(APIView):
    def post(self, request, format=None):
        data = request.data.copy()
        serializer = MasterConfigSerializer(data=data)
        if serializer.is_valid():
            serializer.save()  # Create a new category or subcategory
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


