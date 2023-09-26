from rest_framework import serializers
from .models import MasterConfig


class MasterConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = MasterConfig
        fields = "__all__"

    def create(self, validated_data):
        parent=validated_data["parent"]
        
        if parent is not None:
            try:
                parent_category = MasterConfig.objects.get(id=parent.id)

                if parent_category.max_subcategory_level <= parent_category.children.count():
                    raise serializers.ValidationError("Maximum subcategory level reached for the parent category.")
                validated_data['parent'] = parent_category  # Set the parent field
            except MasterConfig.DoesNotExist:
                raise serializers.ValidationError("Parent category does not exist.")
        else:
            parent_category = None
       
        # Create the new MasterConfig instance with the parent set
        return super().create(validated_data)
