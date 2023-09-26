from django.db import models

class AbstractTime(models.Model):
    """ For Every Database Table """

    created_at = models.DateTimeField("Created Date", auto_now_add=True)
    updated_at = models.DateTimeField("Updated Date", auto_now=True)

    class Meta:
        abstract = True

class MasterConfig(AbstractTime):
    label = models.CharField(max_length=100)
    max_subcategory_level = models.PositiveIntegerField(default=5)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')


    def __str__(self):
        return self.label