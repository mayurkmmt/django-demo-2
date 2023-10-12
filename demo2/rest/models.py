from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save
from rest_framework.authtoken.models import Token
from django.db import models
import uuid

KONG_ROUTE = 1
KONG_SERVICE = 2
KONG_UPSTREAM = 3
KONG_CHOICES = (
    (KONG_ROUTE, 'Kong Route'),
    (KONG_SERVICE, 'Kong Service'),
    (KONG_UPSTREAM, 'Kong Upstream')
)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


class KongEntityMetadata(models.Model):
    name = models.CharField(max_length=255, unique=True, null=False)
    description = models.TextField(blank=True, null=True)
    entity_id = models.UUIDField(default=uuid.uuid4)
    entity_type = models.IntegerField(
        default=KONG_ROUTE,
        choices=KONG_CHOICES
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'rest'
        verbose_name_plural = 'kong_entity_metadatas'
        ordering = ('name',)

    def __str__(self):
        return self.name

    @classmethod
    def get_entity_type_description(cls, entity_type, entity_id):
        try:
            kong_entity_metadata = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
            return kong_entity_metadata.description if kong_entity_metadata else ""
        except Exception as error:
            print("KongEntityMetadata get_entity_type_description ERROR:", error)
            return ""

    @classmethod
    def create_or_update(cls, entity_type, data):
        try:
            entity_id = data["entity_id"] if "entity_id" in data else ""
            description = data["description"] if "description" in data else ""

            if entity_id:
                kong_entity_metadata = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
                if not kong_entity_metadata:
                    cls.objects.create(
                        name=entity_id,
                        entity_id=entity_id,
                        entity_type=entity_type,
                        description=description
                    )
                else:
                    kong_entity_metadata.description = description
                    kong_entity_metadata.save()
        except Exception as error:
            print("KongEntityMetadata create_or_update ERROR:", error)
            return None

class DomainRule(models.Model):

    name = models.CharField(max_length=255, null=False)
    description = models.TextField(blank=True, null=True)
    owner = models.CharField(max_length=36, null=False, blank=False, default="")
    configs = models.JSONField(default=dict, blank=True) # store predefined rules
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [['name', 'owner']]

    @property
    def configsParsed(self):
        config = self.configs
        return config

    def __str__(self):
        return self.name
