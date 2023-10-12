import uuid

from django.db import models
from django.db.models.fields import CharField
from django.db.models.fields.json import JSONField


class Tags(object):
    @classmethod
    def to_dict(cls, li):
        dic = {}
        for l in li:
            i, j = l.split(":")
            dic[i] = j
        return dic

    @classmethod
    def to_list(cls, dic):
        li = []
        for k, v in dic.items():
            li.append("=".join([k, f'"{v}"']))
        return li


# Create your models here.
class GuardStrategy(models.Model):
    # class Meta:
    #    app_label = 'demo2'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    owner = models.UUIDField(editable=True, null=True, db_index=True)
    name = CharField(max_length=72, null=False, blank=False)

    config = JSONField()

    def apply(self):
        """
        1. Search all services with this tag "strategy:id"
        2. Replace the configuration of services and save
        """
        pass
