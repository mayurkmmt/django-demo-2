import csv
import datetime
import json
import logging
import re
import zipfile

import redis
from celery.result import AsyncResult
from django.conf import settings
from django.core.cache import cache
from django.db.models import Sum
from django.http.response import HttpResponse, JsonResponse
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from pyfcm import FCMNotification
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from traffic.api import AliyunLog
from traffic.models import HourTraffic

from config.celery_app import app
from demo2.constants import REDIRECT_DOMAIN_ACTION, UPSTREAM_DOMAIN_ACTION
from demo2.error_codes import (
    PAYLOAD_INVALID,
    QUOTA_REACHED,
    RECORD_NOT_FOUND,
    RECORD_OWNER_ERROR,
    SUBSCRIPTION_NOT_FOUND,
    VIP_ONLY,
)
from demo2.exceptions import QuotaReachedException
from demo2.rest.models import KONG_ROUTE, KongEntityMetadata
from demo2.rest.serializers import (
    CLEAR_CACHE_TASK_NAME,
    ENABLE_HTTPS_TASK_NAME,
    FORCE_HTTPS_TASK_NAME,
    RECOGNIZED_PLUGINS,
    AliyunTrafficResultSerializer,
    DomainCertificatePayloadSerializer,
    DomainCertificatesSerializer,
    DomainPauseRestoreSerializer,
    DomainSerializer,
    DomainSslConfigSerializer,
    IpRestrictionPluginSerializer,
    KongDataDomainSerializer,
    RunTaskSerializer,
    demo2_REDIRECT_PLUGIN_NAME,
    demo2ChallengePluginSerializer,
    demo2RequestLimitPluginSerializer,
)
from demo2.rest.tasks import force_https
from demo2.utils import get_month_day_range
from demo2.utils.cert import CertValidator
from demo2.utils.checker import Checker
from demo2.utils.redis_notification import (
    add_notification,
    get_notifications,
    send_user_fcm_notification,
)
from kong.gateway import (
    KongCertificatesAdmin,
    KongRoutesAdmin,
    KongServicesAdmin,
    KongUpstreamsAdmin,
)
from kong.kong_data_gateway import KongDataRoutesAdmin
from kong.models import (
    KongDataCertificate,
    KongDataRoute,
    KongDataService,
    KongDataSNIS,
)
from strategy.models import Tags

# from demo2_common.models import FCMDevice


"""
  The cname for service is service_id.subscription.zone.ltd
"""

PAGE_SIZE = 100
logger = logging.getLogger(__name__)


class HasCertificateOwnership(BasePermission):
    message = "Ownership error"

    def has_permission(self, request, view):
        if request.method not in ["DELETE", "PATCH"]:
            return super().has_permission(request, view)

        subscription = get_subscription(request.user.username)
        cname = full_cname(subscription)
        owner = subscription.get("cname")

        owner_tags = Tags.to_list({"cname": cname, "owner": owner})
        owner_tags = sorted(owner_tags)

        if request.method == "DELETE":
            if "kong" in view.kwargs["certificate_id"]:
                return True
            kc = KongCertificatesAdmin(owner, cname=cname)
            certificate = kc.get(view.kwargs["certificate_id"])

            is_owned = sorted(certificate.get("tags", [])) == owner_tags
            if not is_owned:
                self.message = RECORD_OWNER_ERROR
                return False

        if request.method == "PATCH":
            kr = KongRoutesAdmin(owner, cname=cname)
            route = kr.get(view.kwargs["route_id"])

            is_owned = sorted(route.get("tags", [])) == owner_tags
            if not is_owned:
                self.message = RECORD_OWNER_ERROR
                return False

        return super().has_permission(request, view)


class SslConfigRestView(viewsets.ViewSet):
    permission_classes = [
        IsAuthenticated,
    ]

    def get(self, request):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        tags = Tags.to_list({"cname": cname, "owner": owner})
        routes = KongDataRoute.objects.filter(tags=tags)
        hosts = []
        for route in routes:
            hosts += route.hosts

        kc = KongCertificatesAdmin(owner, cname=cname)
        kong_certificates = kc.get_by_owner()
        acme_certificates = self.fetch_acme_certs(hosts)

        serializer = DomainCertificatesSerializer(
            data=kong_certificates + acme_certificates
        )
        response = []
        if serializer.is_valid():
            response = serializer.data
        return Response(response)

    def zip(self, request, id):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        kc = KongCertificatesAdmin(owner, cname=cname)
        if "kong_acme" in id:
            certificate = self.fetch_acme_cert(id)
        else:
            certificate = kc.get(id)

        response = HttpResponse(content_type="application/zip")

        zf = zipfile.ZipFile(response, "w")

        zf.writestr("%s_fullchain.pem" % certificate["id"], certificate["cert"])
        zf.writestr("%s_privkey.pem" % certificate["id"], certificate["key"])

        zfname = f"{certificate['snis'][0]}_certs.zip"

        response["Content-Disposition"] = f"attachment; filename={zfname}"
        return response

    @staticmethod
    def fetch_acme_cert(id):
        redis_instance = redis.StrictRedis(
            host=settings.REDIS_HOST,
            password=settings.REDIS_PASSWORD,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DATABASE_KONG_ACME_STORE,
        )

        certificate = {}
        try:
            raw_data = redis_instance.get(id)
        except:
            logger.error(
                f"An error occurred while try to get Kong acme certificate: {id}"
            )

        try:
            data = json.loads(raw_data)
        except:
            logger.error(
                f"Kong acme certificate could not be parsed successfully: {id}"
            )

        host = id.replace("kong_acme:cert_key:", "")
        data.update({"id": id, "snis": [host]})

        certificate = data

        return certificate

    @staticmethod
    def fetch_acme_certs(hosts):
        redis_instance = redis.StrictRedis(
            host=settings.REDIS_HOST,
            password=settings.REDIS_PASSWORD,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DATABASE_KONG_ACME_STORE,
        )

        certificates = []
        for host in hosts:
            key = f"kong_acme:cert_key:{host}"

            try:
                raw_data = redis_instance.get(key)
            except:
                logger.error(
                    f"An error occurred while try to get Kong acme certificate: {key}"
                )
                continue

            # no data was fetch from redis
            if not raw_data:
                continue

            try:
                data = json.loads(raw_data)
            except:
                logger.error(
                    f"Kong acme certificate could not be parsed successfully: {key}"
                )
                continue
            data.update({"id": key, "snis": [host]})

            certificates.append(data)

        return certificates


class DomainSslConfigRestView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, HasCertificateOwnership]

    @swagger_auto_schema(responses={200: DomainCertificatesSerializer()})
    def get(self, request, route_id):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        kr = KongRoutesAdmin(owner, cname=cname)
        route = kr.get(route_id)
        is_force_https = route.get("protocols", []) == ["https"]

        kc = KongCertificatesAdmin(owner, cname=cname)

        kong_certificates = self.find_kong_certificates(kc.get_by_owner(), route)
        acme_certificates = self.fetch_acme_certs(route)

        serializer = DomainCertificatesSerializer(
            data=kong_certificates + acme_certificates
        )
        response = {"certificates": [], "force_https": is_force_https}

        if serializer.is_valid():
            response["certificates"] = serializer.data

        return Response(response)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "force_https": openapi.Schema(
                    type=openapi.TYPE_BOOLEAN,
                ),
            },
        )
    )
    def patch(self, request, route_id):
        serializer = DomainSslConfigSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"field_errors": serializer.errors, "error_code": PAYLOAD_INVALID},
                status=status.HTTP_400_BAD_REQUEST,
            )

        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        # default Kong values for protocols and https_redirect_status_code
        protocols = ["http", "https"]
        https_redirect_status_code = 426

        validated_data = serializer.data

        if validated_data["force_https"]:
            protocols = ["https"]
            https_redirect_status_code = 308

        data = {
            "protocols": protocols,
            "https_redirect_status_code": https_redirect_status_code,
        }

        kr = KongRoutesAdmin(owner, cname=cname)
        rs = kr.update(route_id, data)

        return Response(rs)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "domain": openapi.Schema(
                    type=openapi.TYPE_STRING,
                ),
                "cert": openapi.Schema(
                    type=openapi.TYPE_STRING,
                ),
                "key": openapi.Schema(type=openapi.TYPE_STRING),
            },
        )
    )
    def post(self, request, route_id):
        serializer = DomainCertificatePayloadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"field_errors": serializer.errors, "error_code": PAYLOAD_INVALID},
                status=status.HTTP_400_BAD_REQUEST,
            )

        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        try:
            validator = CertValidator(
                serializer.validated_data["key"], serializer.validated_data["cert"]
            )
            validator.check_cert_match()
            validator.check_hostname_match(serializer.validated_data["domain"])
        except Exception as e:
            str_exception = str(e)
            if "no private key assigned" in str_exception:
                return Response(
                    dict(detail="wrong private related"),
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return Response(dict(detail=str(e)), status=status.HTTP_400_BAD_REQUEST)

        kc = KongCertificatesAdmin(owner, cname=cname)
        response = kc.add(
            serializer.validated_data["domain"],
            serializer.validated_data["cert"],
            serializer.validated_data["key"],
        )

        return Response(response)

    def destroy(self, request, route_id, certificate_id):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        if "kong" in certificate_id:
            response = self.remove_acme_cert(certificate_id)
        else:
            kc = KongCertificatesAdmin(owner, cname=cname)
            response = kc.delete(certificate_id)

        return Response(response)

    def generate_sshkey(self, request, route_id, certificate_id):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        ks = KongCertificatesAdmin(owner, cname)

        domain = request.data.get("domain")

        rs = ks.generate_sshkey(domain)

        return Response(rs)

    @staticmethod
    def remove_acme_cert(certificate_id):
        redis_instance = redis.StrictRedis(
            host=settings.REDIS_HOST,
            password=settings.REDIS_PASSWORD,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DATABASE_KONG_ACME_STORE,
        )

        redis_instance.delete(certificate_id)
        renew_key = certificate_id.replace("cert_key", "renew_config")
        redis_instance.delete(renew_key)

    @staticmethod
    def fetch_acme_certs(route):
        redis_instance = redis.StrictRedis(
            host=settings.REDIS_HOST,
            password=settings.REDIS_PASSWORD,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DATABASE_KONG_ACME_STORE,
        )

        certificates = []
        for host in route["hosts"]:
            key = f"kong_acme:cert_key:{host}"

            try:
                raw_data = redis_instance.get(key)
            except:
                logger.error(
                    f"An error occurred while try to get Kong acme certificate: {key}"
                )
                continue

            # no data was fetch from redis
            if not raw_data:
                continue

            try:
                data = json.loads(raw_data)
            except:
                logger.error(
                    f"Kong acme certificate could not be parsed successfully: {key}"
                )
                continue
            data.update({"id": key, "snis": [host]})

            certificates.append(data)

        return certificates

    @staticmethod
    def find_kong_certificates(certificates, route):
        matching_certificates = []
        matched_certificate_ids = set()

        def add_cert(cert):
            if cert["id"] in matched_certificate_ids:
                return

            matching_certificates.append(cert)
            matched_certificate_ids.add(cert["id"])

        host_map = {host: host for host in route["hosts"]}

        # FIXME: This is slow. Replace this with a solution that does not involve
        # iterating each snis for each certificates.
        for cert in certificates:
            for sni in cert["snis"]:
                is_wildcard = "*" in sni
                if is_wildcard:
                    regex_pattern = sni.replace("*.", "[^\.]+\.")
                    regex_pattern = f"^{regex_pattern}$"

                    for host in route["hosts"]:
                        # if host matches the wildcard domain then this certificate
                        # applies the host. so return the certificate.
                        if re.match(regex_pattern, host):
                            add_cert(cert)

                    continue

                if sni in host_map:
                    add_cert(cert)

        return matching_certificates


def username_to_cname(username):
    cname = str(username).split("-")[0]
    return cname


def get_subscription(username, cname=None):
    base_cname = username_to_cname(username)

    if cname and base_cname not in cname:
        # the cname passed is not owned by the username
        raise PermissionDenied(detail=f"You do not have access to cname '{cname}'")
    elif not cname:
        cname = base_cname

    return app.send_task(
        "plan.get_subscription", kwargs=dict(cname=cname), queue="plan"
    ).get()


def full_cname(subscription):
    return f"{subscription.get('cname')}.{subscription.get('czone')}"


class HasQuota(BasePermission):
    message = QUOTA_REACHED

    def has_permission(self, request, view):
        if request.method not in ["POST", "PATCH"]:
            return super().has_permission(request, view)

        subscription = get_subscription(request.user.username)
        quota = app.send_task(
            "plan.get_quota_by_cname",
            kwargs=dict(cname=subscription.get("cname")),
            queue="plan",
        ).get()

        allowed_domains = quota["DOMAIN"]

        kr = KongRoutesAdmin(subscription.get("cname"), cname=full_cname(subscription))
        current_domains = kr.count_hosts()

        # add 1 for the main domain
        new_hosts = len(kr.filter_hosts(request.data.get("shadows", []))) + 1

        if request.method == "PATCH":
            existing_route = kr.get(view.kwargs["route_id"])
            existing_hosts = len(kr.filter_hosts(existing_route.get("hosts")))

            # factor out existing domains
            current_domains -= existing_hosts

        # add the new hosts to the current domains, if we exceed allowed_domains then we reached the quota
        check = (current_domains + new_hosts) <= allowed_domains
        if not check:
            raise QuotaReachedException()

        return super().has_permission(request, view)


class DomainWidgetView(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    domain_widget_responses = openapi.Response(
        description="Widget count", examples={"application/json": {"running": "int"}}
    )

    @swagger_auto_schema(responses={200: domain_widget_responses})
    @action(detail=False, methods=["get"])
    def domain_stat(self, request, *args, **kwargs):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        kr = KongRoutesAdmin(owner, cname=cname)
        count = kr.count_hosts()
        return Response({"running": count})


class DomainTrafficView(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(responses={200: AliyunTrafficResultSerializer()})
    @action(detail=False, methods=["get"])
    def today_stat(self, request, *args, **kargs):
        """
        今日统计。 总流量，请求次数，命中率
        """
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)

        date = datetime.datetime.now().date()
        trafficStat = HourTraffic.objects.filter(cname=cname, date=date).aggregate(
            pv=Sum("pv"),
            hit_pv=Sum("hit_pv"),
            net_out=Sum("net_out"),
            net_in=Sum("net_in"),
        )
        trafficStat["time"] = date
        return Response(AliyunTrafficResultSerializer(trafficStat).data)

    @swagger_auto_schema(responses={200: AliyunTrafficResultSerializer()})
    @action(detail=False, methods=["get"])
    def monthly_stat(self, request, *args, **kargs):
        # 本月
        # 总流量，请求次数，命中率
        # ,
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)

        date = datetime.datetime.now().date()
        trafficStat = HourTraffic.objects.filter(
            cname=cname, date__range=get_month_day_range(datetime.date.today())
        ).aggregate(
            pv=Sum("pv"),
            hit_pv=Sum("hit_pv"),
            net_out=Sum("net_out"),
            net_in=Sum("net_in"),
        )
        trafficStat["time"] = date
        return Response(AliyunTrafficResultSerializer(trafficStat).data)

    @swagger_auto_schema(responses={200: AliyunTrafficResultSerializer()})
    @action(detail=False, methods=["get"])
    def total_stat(self, request, *args, **kargs):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)

        if subscription.next_bill_date:
            first_day = subscription.created.date()
            last_day = subscription.next_bill_date
        else:
            first_day, last_day = get_month_day_range(datetime.date.today())

        date = datetime.datetime.now().date()
        trafficStat = HourTraffic.objects.filter(
            cname=cname, date__range=[first_day, last_day]
        ).aggregate(
            pv=Sum("pv"),
            hit_pv=Sum("hit_pv"),
            net_out=Sum("net_out"),
            net_in=Sum("net_in"),
        )
        trafficStat["time"] = date
        return Response(AliyunTrafficResultSerializer(trafficStat).data)


class DomainCheckView(viewsets.GenericViewSet):
    permission_classes = [
        IsAuthenticated,
    ]

    @action(detail=True, methods=["post"])
    def check(self, request):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        try:
            route = KongDataRoute.objects.get(pk=request.data.get("route_id"))
        except KongDataRoute.DoesNotExist:
            return Response(
                {"error_code": RECORD_NOT_FOUND}, status=status.HTTP_404_NOT_FOUND
            )

        ip_v6_subscription = app.send_task(
            "subscription.tasks.get_ipv6_subscription",
            kwargs=dict(cname=cname),
            queue="route",
        ).get()

        checker = Checker()

        checkList = [
            "init",
            "source_visit",
            "source_cname",
            "site_visit",
        ]  # "cname_query", "cname_visit",
        if "https" in route.protocols:
            checkList += ["ssl_visit"]
        if ip_v6_subscription["ipv6"]:
            checkList += ["site_visit_v6"]

        checkRs = checker.check(route, checkList)

        return Response(checkRs)


class DomainRestView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, HasQuota]

    page = openapi.Parameter("page", openapi.IN_QUERY, type=openapi.TYPE_STRING)
    perpage = openapi.Parameter("perpage", openapi.IN_QUERY, type=openapi.TYPE_STRING)

    @swagger_auto_schema(
        manual_parameters=[page, perpage], responses={200: DomainSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        base_cname = request.query_params.get("cname")
        cert_status = request.query_params.get("cert_status")
        status = request.query_params.get("status")
        q = request.query_params.get("q")

        subscription = get_subscription(self.request.user.username, base_cname)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        kr = KongDataRoutesAdmin(owner, cname, cert_status, status, q)
        route_list = kr.list(
            request.query_params.get("page", 1),
            request.query_params.get("perpage", PAGE_SIZE),
        )

        domains = []
        i = 0
        total_routes = len(route_list["routes"])
        for r in route_list["routes"]:
            i = i + 1
            logger.info(f"Processing {i} of {total_routes}")

            domain = KongDataDomainSerializer(
                data=r, context={"owner": owner, "cname": cname, "fetch_relation": True}
            )

            description = KongEntityMetadata.get_entity_type_description(
                KONG_ROUTE, r["id"]
            )

            if domain.is_valid():
                domains.append(
                    {"domain": domain.data, "meta": {"description": description}}
                )
            else:
                logger.error(
                    f"[{cname}] Could not display service [{r['service']['id']}]. It might be improperly "
                    f"configured. Error = {domain.errors}"
                )

        return Response(
            {
                "domains": domains,
                "page": route_list["page"],
                "total_pages": route_list["total_pages"],
            }
        )

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "hosts": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "protocols": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "service": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "upstream": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "plugins": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "tags": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "domain_name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="The desc"
                ),
                "domain_action": openapi.Schema(
                    type=openapi.TYPE_STRING, description="The desc"
                ),
            },
        )
    )
    def create(self, request, *args, **kwargs):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        if "domain" not in request.data:
            return Response(
                {"error_code": "Domain is require"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = DomainSerializer(
            data=request.data["domain"],
            context={"cname": cname, "owner": owner, "check_hosts": True},
        )

        if not serializer.is_valid():
            return Response(
                {"field_errors": serializer.errors, "error_code": PAYLOAD_INVALID},
                status=status.HTTP_400_BAD_REQUEST,
            )

        tags = Tags.to_list({"cname": cname, "owner": owner})

        upstream_data = {}
        if serializer.data["domain_action"] == UPSTREAM_DOMAIN_ACTION:
            upstream_data = {
                "name": serializer.validated_data["service"]["host"],
                "tags": tags,
            }

        data = {
            "protocol": serializer.validated_data["service"]["protocol"],
            "host": serializer.validated_data["service"]["host"],
            "port": serializer.validated_data["service"]["protocol"] == "https"
            and 443
            or 80,
            "path": "/",
            "tags": list(
                set(tags + serializer.validated_data["service"].get("tags", []))
            ),
        }

        ks = KongServicesAdmin(owner, cname)

        # create Services
        rs = ks.save(data)
        if "error" in rs:
            return Response(rs)

        service_id = rs.get("id")

        # update the name to cname
        service_update = {"name": "%s.%s" % (service_id[:8], cname)}
        for plugin_data in serializer.validated_data["plugins"]:
            plugin = ks.update_or_create_plugin(service_id, plugin_data)
            if plugin["name"] == demo2_REDIRECT_PLUGIN_NAME:
                service_update.update({"host": f"demo2-redirect.{plugin['id']}"})

        rs = ks.update(service_id, service_update)

        # update route
        route_data = {
            "name": serializer.data["domain_name"],
            "hosts": serializer.validated_data["hosts"],
            "preserve_host": True,
            "tags": data["tags"],
        }
        route_url = "services/%s/routes" % service_id
        r = ks._post(route_url, route_data)

        if upstream_data:
            # create upstream
            ku = KongUpstreamsAdmin(owner, cname)
            upstream = ku.save(upstream_data)

            # add targets to upstream
            for t in serializer.validated_data["upstream"]["targets"]:
                ku.add_target(upstream.get("id"), t["target"])

        # KongEntityMetadata entry with description
        if "description" in request.data["meta"]:
            domain_data = {
                "entity_id": r["id"],
                "description": request.data["meta"]["description"],
            }
            KongEntityMetadata.create_or_update(KONG_ROUTE, domain_data)

        return Response(rs)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "hosts": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "protocols": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "service": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "upstream": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "plugins": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                "tags": openapi.Schema(
                    type=openapi.TYPE_OBJECT, description="The desc"
                ),
                "domain_name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="The desc"
                ),
                "domain_action": openapi.Schema(
                    type=openapi.TYPE_STRING, description="The desc"
                ),
            },
        ),
    )
    def update(self, request, *args, **kwargs):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        if "domain" not in request.data:
            return Response(
                {"error_code": "Domain is require"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = DomainSerializer(
            data=request.data["domain"],
            context={
                "cname": cname,
                "owner": owner,
                "route_id": kwargs.get("route_id"),
                "check_hosts": True,
            },
        )

        if not serializer.is_valid():
            return Response(
                {"field_errors": serializer.errors, "error_code": PAYLOAD_INVALID},
                status=status.HTTP_400_BAD_REQUEST,
            )

        kr = KongRoutesAdmin(owner, cname=cname)
        route = kr.get(kwargs.get("route_id"))
        old_domain = DomainSerializer(
            data=route, context={"cname": cname, "owner": owner, "fetch_relation": True}
        )
        old_domain.is_valid()

        tags = Tags.to_list({"cname": cname, "owner": owner})

        route_update_data = {
            "name": serializer.data["domain_name"],
            "hosts": serializer.validated_data["hosts"],
            "tags": tags,
        }

        # Update the route
        kr.update(kwargs.get("route_id"), route_update_data)

        ks = KongServicesAdmin(owner, cname=cname)
        # we need to update the tags even though the tags in the payload is empty in order to make the tag removal
        ks.update(
            route["service"]["id"],
            {
                "tags": list(
                    set(tags + serializer.validated_data["service"].get("tags", []))
                )
            },
        )

        logger.info(
            "====>>>> DomainRestView update UPSTREAM_DOMAIN_ACTION: %s"
            % (UPSTREAM_DOMAIN_ACTION)
        )
        logger.info(
            "====>>>> DomainRestView update old_domain.data: %s" % (old_domain.data)
        )
        logger.info(
            "====>>>> DomainRestView update serializer.data: %s" % (serializer.data)
        )
        logger.info(
            "====>>>> DomainRestView update serializer.validated_data: %s"
            % (serializer.validated_data)
        )

        if (
            "domain_action" in old_domain.data
            and old_domain.data["domain_action"] == UPSTREAM_DOMAIN_ACTION
        ):
            ku = KongUpstreamsAdmin(owner, cname=cname)
            upstream = ku.get_by_name(old_domain.data["domain_name"])
            is_still_service_upstream = (
                serializer.data["domain_action"] == UPSTREAM_DOMAIN_ACTION
            )

            # service is still using upstream
            if is_still_service_upstream:
                service_update_payload = {
                    "protocol": serializer.validated_data["service"]["protocol"]
                }

                if (
                    serializer.data["service"]["protocol"]
                    != old_domain.data["service"]["protocol"]
                ):
                    service_update_payload.update(
                        {
                            "port": serializer.validated_data["service"]["protocol"]
                            == "https"
                            and 443
                            or 80
                        }
                    )

                if serializer.data["domain_name"] != old_domain.data["domain_name"]:
                    ku.update(
                        upstream.get("id"), {"name": serializer.data["domain_name"]}
                    )
                    service_update_payload.update(
                        {"host": serializer.data["domain_name"]}
                    )

                ks.update(route["service"]["id"], service_update_payload)

                upstream_targets = {
                    t.get("target"): t for t in ku.get_targets(upstream.get("id"))
                }

                for t in serializer.validated_data["upstream"]["targets"]:
                    target = t["target"]
                    # skip creation of this "t" because it already exists as an upstream target
                    is_existing = target in upstream_targets
                    if is_existing:
                        upstream_targets.pop(target)
                        continue

                    # create
                    ku.add_target(upstream.get("id"), target)

                # whatever is left in upstream_targets will be deleted
                for _, target in upstream_targets.items():
                    ku.delete_target(upstream.get("id"), target.get("id"))
            else:
                # service is not using upstream anymore so we delete it
                ku.delete(upstream.get("id"))
        elif (
            "domain_action" in old_domain.data
            and old_domain.data["domain_action"] == REDIRECT_DOMAIN_ACTION
        ):
            is_still_service_redirect = (
                serializer.data["domain_action"] == REDIRECT_DOMAIN_ACTION
            )

            # service is now changed to upstream, so we need to create the upstream
            if not is_still_service_redirect:
                # create upstream
                ku = KongUpstreamsAdmin(owner, cname)
                upstream_data = {
                    "name": serializer.validated_data["service"]["host"],
                    "tags": tags,
                }

                upstream = ku.save(upstream_data)

                # add targets to upstream
                for t in serializer.validated_data["upstream"]["targets"]:
                    ku.add_target(upstream.get("id"), t["target"])

                ks.update(
                    old_domain.data["service"]["id"],
                    {"host": serializer.validated_data["service"]["host"]},
                )

        self.update_plugins(serializer, old_domain, ks)

        # KongEntityMetadata entry with description
        if "description" in request.data["meta"]:
            domain_data = {
                "entity_id": route["id"],
                "description": request.data["meta"]["description"],
            }
            KongEntityMetadata.create_or_update(KONG_ROUTE, domain_data)

        return Response(serializer.data)

    def update_plugins(
        self, new_domain_serializer, old_domain_serializer, kong_services_admin
    ):
        service_id = old_domain_serializer.data["service"]["id"]

        plugin_name_to_id = {
            p["name"]: p["id"] for p in kong_services_admin.get_plugins(service_id)
        }

        for plugin_data in new_domain_serializer.validated_data["plugins"]:
            is_active_plugin = plugin_data["name"] in plugin_name_to_id.keys()
            update_plugin_to_disabled = is_active_plugin and not plugin_data.get(
                "enabled", True
            )
            # if the plugin is to be disabled we skip if the data passed the serializer validation.
            # this is done for scenarios where the user "clears" the plugin value, but decided to
            # disable the plugin altogether. skipping the data validation will enable the user
            # to disable the plugin without forcing to provide the required plugin values.
            if update_plugin_to_disabled:
                kong_services_admin.update_or_create_plugin(
                    service_id,
                    {"enabled": False},
                    plugin_name_to_id.get(plugin_data["name"]),
                )
                continue

            if not is_active_plugin and not plugin_data.get("enabled", True):
                logger.info(
                    f"New plugin {plugin_data['name']} is in a disabled state. Skipping."
                )
                continue

            plugin_id = plugin_name_to_id.get(plugin_data["name"])
            plugin = kong_services_admin.update_or_create_plugin(
                service_id, plugin_data, plugin_id
            )
            if plugin["name"] == demo2_REDIRECT_PLUGIN_NAME:
                kong_services_admin.update(
                    service_id, {"host": f"demo2-redirect.{plugin['id']}"}
                )

        # start: delete plugins
        existing_plugins = set(plugin_name_to_id)
        plugins_in_update = {
            p["name"] for p in new_domain_serializer.validated_data["plugins"]
        }
        # subtract the new plugins to the existing, the difference are the once we delete
        # i.e. if the plugins are not in plugins_in_update, then we should remove those plugins
        plugin_names_to_delete = existing_plugins - plugins_in_update
        for plugin_name_to_delete in plugin_names_to_delete:
            # Skips the unrecognized plugin to avoid deleting it automatically
            if plugin_name_to_delete not in RECOGNIZED_PLUGINS:
                continue

            plugin_id = plugin_name_to_id.get(plugin_name_to_delete)
            if plugin_id:
                kong_services_admin.delete_plugin(service_id, plugin_id)

    def destroy(self, request, *args, **kwargs):
        cname = request.data.get("cname")

        subscription = get_subscription(self.request.user.username, cname)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        route_id = kwargs.get("route_id")

        kr = KongRoutesAdmin(owner, cname=cname)

        # store it before we delete so we can access the service id
        route = kr.get(route_id)

        domain_serializer = DomainSerializer(
            data=route, context={"cname": cname, "owner": owner, "fetch_relation": True}
        )
        if not domain_serializer.is_valid():
            return Response(
                {"error_code": RECORD_NOT_FOUND}, status=status.HTTP_404_NOT_FOUND
            )

        domain_name = domain_serializer.data["domain_name"]

        # delete route
        kr.delete(route_id)

        ks = KongServicesAdmin(owner, cname)
        # delete service
        rs = ks.delete(route["service"]["id"])

        # delete upstream forcefully when delete route/domain
        # if domain_serializer.data['domain_action'] == UPSTREAM_DOMAIN_ACTION:
        ku = KongUpstreamsAdmin(owner, cname=cname)
        upstream = ku.get_by_name(domain_name)
        if upstream:
            ku.delete(upstream["id"])
        else:
            logger.info(f"[{cname}] Upstream for domain {domain_name} not found.")

        # Delete Certificate
        certificates = KongDataCertificate.objects.filter(
            tags__overlap=Tags.to_list({"owner": owner})
        )
        for name in route["hosts"]:
            certificate_id = f"kong_acme:cert_key:{name}"
            DomainSslConfigRestView.remove_acme_cert(certificate_id)
            for cert in certificates:
                if name in cert.snis:
                    snis = KongDataSNIS.objects.filter(certificate_id=cert.id)
                    for sni in snis:
                        sni.delete()
                    cert.delete()
                    break

        # delete metadata
        KongEntityMetadata.objects.filter(entity_id=route_id).delete()

        return Response(rs)


class ConfigureSubscriptionRestView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    configure_subscription_responses = openapi.Response(
        description="Success",
        examples={"application/json": {"ipv6": "string", "customize_ports": "string"}},
    )

    @swagger_auto_schema(responses={200: configure_subscription_responses})
    def get(self, request):
        subscription = get_subscription(request.user.username)

        cname = full_cname(subscription)

        ip_v6_subscription = app.send_task(
            "subscription.tasks.get_ipv6_subscription",
            kwargs=dict(cname=cname),
            queue="route",
        ).get()

        return Response(
            {
                "ipv6": ip_v6_subscription["ipv6"],
                "customize_ports": (
                    subscription["customize_ports"]["ports"]
                    if subscription
                    and "customize_ports" in subscription
                    and subscription["customize_ports"]
                    and "ports" in subscription["customize_ports"]
                    else []
                ),
            }
        )

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "ipv6": openapi.Schema(
                    type=openapi.TYPE_STRING,
                ),
            },
        )
    )
    def post(self, request):
        subscription = get_subscription(request.user.username)
        if not subscription.get("plan", None):
            return Response(
                {"error_code": VIP_ONLY}, status=status.HTTP_401_UNAUTHORIZED
            )

        cname = full_cname(subscription)

        logger.info(f"ConfigureSubscriptionRestView post: request.data {request.data}")

        ipv6 = request.data["ipv6"] if "ipv6" in request.data else True

        if ipv6:
            logger.info(f"send_task subscription.tasks.enable_ipv6_subscription")
            app.send_task(
                "subscription.tasks.enable_ipv6_subscription",
                kwargs=dict(cname=cname),
                queue="route",
            ).get()
        else:
            logger.info(f"send_task subscription.tasks.disabled_ipv6_subscription")
            app.send_task(
                "subscription.tasks.disabled_ipv6_subscription",
                kwargs=dict(cname=cname),
                queue="route",
            ).get()

        return Response({"success": True})


class RunTasksView(viewsets.ViewSet):
    def user_background_tasks_key(self):
        return "background-tasks-%s" % self.request.user.username

    def get(self, request):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user_tasks_key = self.user_background_tasks_key()
        user_tasks_ids = cache.get(user_tasks_key)
        if not user_tasks_ids:
            return Response([])

        user_tasks = []

        for task in json.loads(user_tasks_ids):
            res = AsyncResult(task["id"], app=app)

            celery_task = {
                "name": task["name"],
                "status": res.status,
                "result": res.result,
                "date_done": res.date_done,
            }

            user_tasks.append(celery_task)

        return Response(user_tasks)

    def post(self, request):
        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        task_serializer = RunTaskSerializer(data=request.data)
        if not task_serializer.is_valid():
            return Response(
                {"error_code": PAYLOAD_INVALID}, status=status.HTTP_400_BAD_REQUEST
            )

        task_title = "TaskScheduled"
        task_name = task_serializer.validated_data["task"]
        if task_name == FORCE_HTTPS_TASK_NAME:
            if (
                "options" in task_serializer.data
                and "enabled" in task_serializer.data["options"]
            ):
                enabled = task_serializer.data["options"]["enabled"]
                task_title = "EnableForceHTTPS" if enabled else "DisableForceHTTPS"

                result = app.send_task(
                    "domain.batch_actions.force_https",
                    kwargs=dict(
                        routeIds=request.data["ids"],
                        cname=cname,
                        owner=owner,
                        enable=enabled,
                        user_id=request.user.id,
                    ),
                    queue="domain",
                )
            else:
                return Response(
                    {"error_code": PAYLOAD_INVALID}, status=status.HTTP_400_BAD_REQUEST
                )

        elif task_name == ENABLE_HTTPS_TASK_NAME:
            task_title = "EnableHTTPS"
            for route_id in request.data["ids"]:
                result = app.send_task(
                    "domain.enable_https",
                    kwargs=dict(
                        route_id=route_id,
                        cname=cname,
                        owner=owner,
                        user_id=request.user.id,
                    ),
                    queue="domain",
                )

        elif request.data["task"] == CLEAR_CACHE_TASK_NAME:
            task_title = "ClearCache"
            result = app.send_task(
                "domain.batch_actions.clear_cache",
                kwargs=dict(
                    ids=request.data["ids"],
                    cname=cname,
                    owner=owner,
                    user_id=request.user.id,
                ),
                queue="domain",
            )

        user_tasks_ids = []
        user_tasks_key = self.user_background_tasks_key()
        user_tasks_json = cache.get(user_tasks_key)

        if user_tasks_json:
            user_tasks_ids = json.loads(user_tasks_json)

        task = {"name": task_title, "id": result.id}
        user_tasks_ids = [task] + user_tasks_ids

        # store 6 items at a time. let's change this if there a need to display all of the task.
        user_tasks_ids = user_tasks_ids[:6]

        # 2 days
        cache_expire_seconds = 86400 * 2
        cache.set(user_tasks_key, json.dumps(user_tasks_ids), cache_expire_seconds)

        return Response({"success": True})


class TrafficStatisticsView(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"])
    def get_overview_data(self, request):
        from_time = request.query_params.get("start", "").replace("+", " ")
        to_time = request.query_params.get("end", "").replace("+", " ")

        from_time_obj = datetime.datetime.strptime(from_time, "%Y-%m-%d %H:%M:%S")
        to_time_obj = datetime.datetime.strptime(to_time, "%Y-%m-%d %H:%M:%S")

        subscription = get_subscription(self.request.user.username)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)

        domain_queryset = HourTraffic.objects.filter(cname=cname)
        domain_queryset_count = domain_queryset.count()

        get_by_cname = request.query_params.get("get_by_cname", None)
        aliyun_log = AliyunLog()

        interval, time_unit = aliyun_log.get_series_from_range(
            from_time_obj, to_time_obj
        )
        series_info = {"interval": interval, "time_unit": time_unit}

        if get_by_cname:
            traffic = aliyun_log.fetch_cname_aggregate_traffic(
                get_by_cname,
                from_time=from_time_obj,
                to_time=to_time_obj,
                filter_limit=100000000,
            )
            trafficDomain = aliyun_log.fetch_domain_aggregate_traffic_by_cname(
                get_by_cname,
                from_time=from_time_obj,
                to_time=to_time_obj,
                filter_limit=100000000,
            )

            logs = []
            for log in traffic:
                log_obj = log.get_contents()
                if "cname" in log_obj and log_obj["cname"] != "null":
                    logs.append(log_obj)

            return JsonResponse(
                {
                    "success": True,
                    "logs": logs,
                    "domains": [log.get_contents() for log in trafficDomain],
                    "series_info": series_info,
                }
            )

        page = int(request.query_params.get("page", 1))

        aliyun_limit = 25
        offset_start = (page * aliyun_limit) - aliyun_limit
        offset_end = offset_start + aliyun_limit

        # If result is less then the limit we can assume there is no more data to fetch
        has_more = domain_queryset_count >= (page * aliyun_limit)

        # domain_queryset = domain_queryset.order_by('domain')[offset_start:offset_end]
        # domains = [d.domain for d in domain_queryset]
        domains = (
            KongDataRoute.objects.filter(tags__icontains=cname)
            .order_by("-updated_at")
            .values_list("name", flat=True)
        )
        domains = list(filter(None, list(set(domains))))
        domains = [domain.replace("-", ".") for domain in domains]

        logger.info(f"get_overview_data: domains {domains}")

        logs = []
        if domains:
            traffic = AliyunLog().fetch_domain_aggregate_traffic(
                domains,
                from_time=from_time_obj,
                to_time=to_time_obj,
                filter_limit=100000000,
            )
            for log in traffic:
                log_obj = log.get_contents()
                if "domain" in log_obj and log_obj["domain"] != "null":
                    kong_route = KongDataRoute.objects.filter(
                        hosts__overlap=[log_obj["domain"]]
                    ).first()
                    if kong_route:
                        domain_name = kong_route.name.replace("-", ".")
                        if domain_name == log_obj["domain"]:
                            log_obj["shadow"] = log_obj["domain"]
                        else:
                            log_obj["shadow"] = log_obj["domain"]
                            log_obj["domain"] = domain_name
                    logs.append(log_obj)
            has_more = False

        return JsonResponse(
            {
                "success": True,
                "logs": logs,
                "has_more": has_more,
                "series_info": series_info,
            }
        )

    def get_access_logs(self, request):
        all_domain = request.data.get("domains", [])

        query_date = request.data.get("date", None)
        from_time = None
        to_time = None
        if query_date:
            from_time = f"""{query_date} 00:00:00"""
            to_time = f"""{query_date} 23:59:59"""

        filter_by_ip_address = request.data.get("ip_address", None)
        filter_by_http_status_response = request.data.get("http_status_response", None)
        filter_by_cache = request.data.get("cache", None)

        traffic = AliyunLog().fetchAccesslog(
            all_domain,
            fromTime=from_time,
            toTime=to_time,
            filterByIpAddress=filter_by_ip_address,
            filterByHttpStatusResponse=filter_by_http_status_response,
            filterByStatusCodes=request.data.get("status_codes", None),
            filterByCache=filter_by_cache,
            filterByRequestTime=request.data.get("request_time", None),
            filterByBodyBytesSent=request.data.get("body_bytes_sent", None),
        )

        rs = [log.get_contents() for log in traffic]

        return rs

    @action(detail=False, methods=["post"])
    def access_logs(self, request):
        rs = self.get_access_logs(self.request)

        return JsonResponse(rs, safe=False)

    @action(detail=False, methods=["post"])
    def download_access_logs(self, request):
        rs = self.get_access_logs(self.request)

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="access_logs.csv"'

        expected_fields = [
            "remote_addr",
            "cache_status",
            "time_local",
            "host",
            "method",
            "uri",
            "status",
            "request_size",
            "body_bytes_sent",
            "request_time",
        ]
        writer = csv.DictWriter(response, fieldnames=expected_fields)
        writer.writeheader()

        for lo in rs:
            try:
                writer.writerow({field: lo[field] for field in expected_fields})
            except:
                pass

        return response


class UserDomainView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, HasQuota]

    user_domain_responses = openapi.Response(
        description="Success", examples={"application/json": {"domains": ["string"]}}
    )

    @swagger_auto_schema(responses={200: user_domain_responses})
    def list(self, request, *args, **kwargs):
        base_cname = request.query_params.get("cname")
        q = request.query_params.get("search")

        subscription = get_subscription(self.request.user.username, base_cname)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        cname = full_cname(subscription)
        owner = subscription.get("cname")

        kr = KongDataRoutesAdmin(owner=owner, cname=cname, q=q)
        route_list = kr.list(
            request.query_params.get("page", 1),
            request.query_params.get("page_size", 100),
        )

        domains = []
        for r in route_list["routes"]:
            if "hosts" in r and len(r["hosts"]) > 0:
                domains.extend(r["hosts"])

        return Response({"domains": list(set(domains))})


class DomainPauseRestoreView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, HasQuota]

    def post(self, request):
        paused = request.data.get("paused", False)

        pause_restore_serializer = DomainPauseRestoreSerializer(data=request.data)
        if not pause_restore_serializer.is_valid():
            return Response(
                {"error_code": PAYLOAD_INVALID}, status=status.HTTP_400_BAD_REQUEST
            )

        if paused:
            routes = KongDataRoute.objects.filter(
                hosts__overlap=request.data["hosts"]
            ).exclude(tags__overlap=["paused=1"])

            for route in routes:
                service = KongDataService.objects.get(pk=route.service_id)
                service.tags.append("paused=1")
                route.tags.append("paused=1")
                service.save()
                route.save()
        else:
            routes = KongDataRoute.objects.filter(hosts__overlap=request.data["hosts"])

            for route in routes:
                service = KongDataService.objects.get(pk=route.service_id)
                if service and service.tags and "paused=1" in service.tags:
                    service.tags.remove("paused=1")
                    service.save()
                if route and route.tags and "paused=1" in route.tags:
                    route.tags.remove("paused=1")
                    route.save()

        return Response({"success": True})


class FCMRegisterView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if "token" not in request.data:
            raise ValueError("token is required.")

        # device, _created = FCMDevice.objects.get_or_create(user_id=request.user.id)
        # device.registration_id = request.data['token']
        # device.save()

        return Response({"success": True})


class notifyView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_notifications = []
        notifications = get_notifications(request.user.id)
        notifications = list(notifications.values())
        for notification in notifications:
            notification = json.loads(notification.decode("utf-8"))["message"]
            user_notifications.append(notification)
        return Response({"user_notifications": user_notifications})

    def post(self, request):
        if "type" not in request.data:
            raise ValueError("type is required.")
        send_user_fcm_notification(request.user.id, request.data["type"])
        return Response({"success": True})
