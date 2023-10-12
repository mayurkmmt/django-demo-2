import re
import logging
import json

from config.celery_app import app

from celery.result import allow_join_result

from django.contrib.auth.models import User

logger = logging.getLogger(__name__)


class ZoneManagement:

    @classmethod
    def get_admin_url(cls, cname):
        cname = re.sub(r'\.[a-z0-9]{0,3}\.net$', '', cname)
        try:
            user = User.objects.filter(username__icontains=cname).last()
            if user and user.oidc_profile and user.oidc_profile.realm:
                realm_name = user.oidc_profile.realm.name
                with allow_join_result():
                    rs_url = app.send_task(
                        "route.zone.fetch_admin_url_by_realm_name",
                        kwargs=dict(realm_name=realm_name, username=user.username),
                        queue='route'
                    )
                    rs_url = json.loads(rs_url.get())
                logging.info(rs_url)

                if rs_url and "url" in rs_url and rs_url["url"]:
                    return rs_url["url"]
        except Exception as e:
            logger.error('Failed to fetch_admin_url_by_realm_name %s', str(e))

        return ""
