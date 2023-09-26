from django.urls import path
from .views import CreateCategoryOrSubcategoryView

urlpatterns = [
    path("v1/addcategory/", CreateCategoryOrSubcategoryView.as_view()),]

    