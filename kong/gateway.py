"""
https://docs.konghq.com/1.4.x/admin-api/
"""
import logging
from json import JSONDecodeError
from urllib.parse import urljoin

import requests
from django.conf import settings
from requests.exceptions import ConnectionError

from demo2.rest import serializers as demo2_serializer
from demo2.rest.models import KONG_ROUTE, KongEntityMetadata
from kgateway.exceptions import GatewayConnectionException, GatewayValidationException
from strategy.models import Tags

logger = logging.getLogger(__name__)

KONG_ADMIN_AUTH_HEADER = {"apikey": settings.KONG_ADMIN_API_KEY}

PAGE_SIZE = 100


class KongAdmin:
    def __init__(self):
        self.host = settings.KONG_ADMIN_HOST
        self.headers = KONG_ADMIN_AUTH_HEADER

    def get_url(self, path: str) -> str:
        return urljoin(self.host, path)

    def get_headers(self, headers) -> dict:
        return self.headers | headers

    def request(self, method: str, path: str, **kwargs) -> dict:
        url = self.get_url(path)
        headers = self.get_headers(kwargs.pop("headers", {}))

        try:
            response = requests.request(method, url, headers=headers, **kwargs)
        except ConnectionError:
            raise GatewayConnectionException()

        try:
            data = response.json()
        except JSONDecodeError:
            data = None

        if response.status_code >= 300:
            logger.info(f"Kong gateway request error ============>: {data}")
            raise GatewayValidationException(
                status_code=response.status_code, context=data
            )

        return data

    def _get(self, path: str, params: dict = None) -> dict:
        return self.request("get", path, params=params)

    def _post(self, path: str, json: dict = None) -> dict:
        return self.request("post", path, json=json)

    def put(self, path: str, json: dict = None) -> dict:
        return self.request("put", path, json=json)

    def _patch(self, path: str, json: dict = None) -> dict:
        return self.request("patch", path, json=json)

    def _delete(self, path: str) -> dict:
        return self.request("delete", path)

    def _list(self, path: str, params: dict = None):
        if params is None:
            params = {}

        params.update({"size": PAGE_SIZE})

        data = []
        while True:
            response = self._get(path, params=params)
            current_page_data = response["data"]

            data += current_page_data

            if response.get("offset"):
                params.update({"offset": response.get("offset")})
            else:
                break

        return data

    def get_by_cname(self):
        return self._get(
            self.path, params={"tags": Tags.to_list({"cname": self.cname})}
        )

    def get_by_owner(self):
        params = {"tags": [f'cname="{self.cname}"', f'owner="{self.owner}"']}

        return self._list(self.path, params)

    def save(self, data):
        return self._post(f"{self.path}", data)

    def update(self, id, data):
        return self._patch(f"{self.path}/{id}", data)


class KongServicesAdmin(KongAdmin):
    path = "services"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongAdmin.__init__(self)

    def get(self, service_id):
        # TODO: Add additional filter of owner/cname so only right users can fetch data
        return self._get(f"{self.path}/{service_id}")

    def delete(self, service_id):
        return self._delete(f"{self.path}/{service_id}")

    def get_plugins(self, service_id):
        return self._list(f"{self.path}/{service_id}/plugins")

    def get_plugin(self, service_id, plugin_id):
        return self._get(f"{self.path}/{service_id}/plugins/{plugin_id}")

    def update_or_create_plugin(self, service_id, data, plugin_id=None):
        # if data and "name" in data and data["name"] == demo2_serializer.IP_RESTRICTION_PLUGIN_NAME:
        #     data["name"] = demo2_serializer.demo2_IP_RESTRICTION_PLUGIN_NAME
        if plugin_id:
            return self._patch(f"{self.path}/{service_id}/plugins/{plugin_id}", data)

        return self._post(f"{self.path}/{service_id}/plugins", data)

    def delete_plugin(self, service_id, plugin_id):
        return self._delete(f"{self.path}/{service_id}/plugins/{plugin_id}")


class KongPluginsAdmin(KongAdmin):
    path = "plugins"

    def __init__(self, kong_id, kong_type="services"):
        self.kong_id = kong_id
        self.kong_type = kong_type

        KongAdmin.__init__(self)

    def get_by_id(self):
        return self._get(f"{self.kong_type}/{self.kong_id}/{self.path}")


DEFAULT_UPSTREAM_PORT = 80


class KongUpstreamsAdmin(KongAdmin):
    path = "upstreams"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongAdmin.__init__(self)

    @staticmethod
    def target_with_port(target):
        if ":" not in target:
            return f"{target}:{DEFAULT_UPSTREAM_PORT}"

        return target

    def add_target(self, upstream_id, target):
        data = {
            "target": self.target_with_port(target),
            "tags": Tags.to_list({"cname": self.cname, "owner": self.owner}),
        }

        return self._post(f"{self.path}/{upstream_id}/targets", data)

    def delete_target(self, upstream_id, target_id):
        return self._delete(f"{self.path}/{upstream_id}/targets/{target_id}")

    def get_targets(self, upstream_id):
        # TODO: handle pagination
        response = self._get(f"{self.path}/{upstream_id}/targets")

        return response.get("data")

    def get_by_name(self, name):
        response = self._get(f"{self.path}/{name}")
        if "error" in response:
            return None

        return response

    def delete(self, upstream_id):
        return self._delete(f"{self.path}/{upstream_id}")


class KongRoutesAdmin(KongAdmin):
    path = "routes"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongAdmin.__init__(self)

    def list(self, offset=None, page_size=PAGE_SIZE):
        params = {
            "tags": [f'cname="{self.cname}"', f'owner="{self.owner}"'],
            "size": page_size,
        }
        if offset:
            params.update({"offset": offset})

        logger.info(f"[{self.cname}] Fetching routes")
        response = self._get("routes", params=params)
        routes_raw = response["data"]
        logger.info(f"[{self.cname}] Routes fetched: {len(routes_raw)}")

        return {"routes": routes_raw, "offset": response.get("offset")}

    def filter_hosts(self, hosts):
        if hosts:
            return list(
                filter(
                    None, list(set(((",".join(hosts)).replace("www.", "")).split(",")))
                )
            )
        return []

    def count_hosts(self):
        route_list = []
        response = self.list()
        route_list += response["routes"]
        if response.get("offset") is not None:
            while True:
                response = self.list(offset=response["offset"])
                route_list += response["routes"]
                if response["offset"] is None:
                    break

        count = sum([len(self.filter_hosts(r["hosts"])) for r in route_list])

        return count

    def get(self, route_id):
        return self._get(f"{self.path}/{route_id}")

    def delete(self, route_id):
        return self._delete(f"{self.path}/{route_id}")

    def force_https(self, route_id, enable):
        protocols = ["http", "https"]
        https_redirect_status_code = 426

        if enable:
            protocols = ["https"]
            https_redirect_status_code = 308

        data = {
            "protocols": protocols,
            "https_redirect_status_code": https_redirect_status_code,
        }

        self.update(route_id, data)


class KongCertificatesAdmin(KongAdmin):
    path = "certificates"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongAdmin.__init__(self)

    def get(self, certificate_id):
        return self._get(f"{self.path}/{certificate_id}")

    def add(self, sni, certificate, key):
        data = {
            "snis": [sni],
            "cert": certificate,
            "key": key,
            "tags": Tags.to_list({"cname": self.cname, "owner": self.owner}),
        }

        return self._post(self.path, data)

    def delete(self, certificate_id):
        return self._delete(f"{self.path}/{certificate_id}")

    def generate_sshkey(self, domain):
        return self._post(f"acme", {"host": domain})
