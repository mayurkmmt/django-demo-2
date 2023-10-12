from json import JSONDecodeError
from kgateway.exceptions import KongDatabaseConnectionException
from strategy.models import Tags
from kong.models import KongDataRoute, KongDataUpstream, KongDataPlugin, KongDataCertificate, KongDataService
from requests.exceptions import ConnectionError
import logging
from kong.kongdata_serializer import prepare_routes_data
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q

logger = logging.getLogger(__name__)

PAGE_SIZE = 100
DEFAULT_UPSTREAM_PORT = 80

class KongDataAdmin:
    def __init__(self):
        pass

    def request(self, method: str, path: str, **kwargs) -> dict:
        logger.info(f"=================>>>>>>>>>>> KongDataAdmin request path: {path}")
        logger.info(f"=================>>>>>>>>>>> KongDataAdmin request method: {method}")
        params = kwargs.get("params")
        logger.info(f"=================>>>>>>>>>>> KongDataAdmin request params: {params}")

        if path == "services":
            queryset = KongDataService.objects.all()
        elif path == "routes":
            queryset = KongDataRoute.objects.all().order_by('-updated_at')
            if "cname" in params and params["cname"]:
                queryset = KongDataRoute.objects.filter(tags__icontains=params["cname"]).order_by('-updated_at')
            if "q" in params and params["q"]:
                queryset = queryset.filter(Q(name__icontains=params["q"]) | Q(hosts__icontains=params["q"]))
            if "cert_status" in params and params["cert_status"]:
                if params['cert_status'] == 'https':
                    queryset = queryset.filter(protocols__overlap=['https'])
                elif params['cert_status'] == 'force':
                    queryset = queryset.filter(protocols=['https'])
                elif params['cert_status'] == 'http':
                    queryset = queryset.filter(protocols__overlap=['http'])
            if "status" in params and params["status"]:
                if params['status'] == 'disabled':
                    queryset = queryset.filter(tags__overlap=['paused=1'])
                elif params['status'] == 'running':
                    queryset = queryset.exclude(tags__overlap=['paused=1'])
        elif path == "plugins":
            queryset = KongDataPlugin.objects.all()
        elif path == "upstreams":
            queryset = KongDataUpstream.objects.all()
        elif path == "certificates":
            queryset = KongDataCertificate.objects.all()
        else:
            queryset = None

        try:
            page_size = int(params["size"])

            paginator = Paginator(queryset, page_size)
            response = paginator.page(int(params["page"])).object_list
            logger.info(f"=================>>>>>>>>>>> KongDataAdmin response: {response}")
        except PageNotAnInteger:
            response = []
            logger.info(f"=================>>>>>>>>>>> KongDataAdmin PageNotAnInteger Error")
        except EmptyPage:
            response = []
            logger.info(f"=================>>>>>>>>>>> KongDataAdmin EmptyPage Error")
        except ConnectionError:
            raise KongDatabaseConnectionException()

        return {"data": response, "page": int(params["page"]), "total_pages": paginator.page_range.stop - 1}

    def _get(self, path: str, params: dict = None) -> dict:
        return self.request("get", path, params=params)

    def _list(self, path: str, params: dict = None):
        params = params if params else {}
        params.update({'size': PAGE_SIZE})
        response = self._get(path, params=params)
        current_page_data = response['data']
        return current_page_data

    def get_by_cname(self):
        return self._get(self.path, params={"cname": self.cname})

    def get_by_owner(self):
        return self._list(self.path, {"cname": self.cname, "owner": self.owner})

class KongDataServicesAdmin(KongDataAdmin):
    path = "services"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongDataAdmin.__init__(self)

    def get(self, service_id):
        return self._get(f"{self.path}/{service_id}")

    def get_plugins(self, service_id):
        return self._list(f"{self.path}/{service_id}/plugins")

    def get_plugin(self, service_id, plugin_id):
        return self._get(f"{self.path}/{service_id}/plugins/{plugin_id}")

class KongDataRoutesAdmin(KongDataAdmin):
    # {
    #     "domains": [
    #         {
    #             "domain": {
    #                 "id": "00062e21-b44a-4f65-bb39-eaf4bfdb9142",
    #                 "hosts": [
    #                     "test5899.bm.kaicdn.com",
    #                     "test5899.bm.kaicdn.com",
    #                     "bm.kaicdn.com",
    #                     "a.bm.kaicdn.com",
    #                     "a0000001.bm.kaicdn.com"
    #                 ],
    #                 "protocols": [
    #                     "http",
    #                     "https"
    #                 ],
    #                 "service": {
    #                     "port": 80,
    #                     "id": "e695910f-ad64-4f7c-8b29-4af137ee88a1",
    #                     "protocol": "https",
    #                     "host": "test5899-bm-kaicdn-com",
    #                     "tags": [
    #                         "cname=\"26af6e94.yk1.net\"",
    #                         "owner=\"26af6e94\""
    #                     ]
    #                 },
    #                 "upstream": {
    #                     "id": "aa68ad40-8ab0-43cd-a405-dc6ba0b1eb56",
    #                     "targets": [
    #                         {
    #                             "id": "7e5a64f1-a0d2-43d3-be41-91fbb34995ab",
    #                             "target": "140.116.207.99:80"
    #                         }
    #                     ]
    #                 },
    #                 "plugins": [],
    #                 "tags": [
    #                     "cname=\"26af6e94.yk1.net\"",
    #                     "owner=\"26af6e94\""
    #                 ]
    #             },
    #             "meta": {
    #                 "description": ""
    #             }
    #         }
    #     ],
    #     "offset": "WyIwMDBiNzFiNS02ODcxLTQzMDAtOGE3Zi0xOTcyMjBkNDBlODIiXQ"
    # }

    path = "routes"

    def __init__(self, owner, cname=None, cert_status=None, status=None, q=None):
        self.owner = owner
        self.cname = cname
        self.cert_status = cert_status
        self.status = status
        self.q = q

        KongDataAdmin.__init__(self)

    def list(self, page=0, page_size=PAGE_SIZE, cert_status=None, status=None):
        params = {
            "cname": self.cname,
            "owner": self.owner,
            "size": page_size,
            "page": page,
            "cert_status": self.cert_status,
            "status": self.status,
            "q": self.q
        }

        logger.info(f"[{self.cname}] Fetching routes")
        response = self._get("routes", params=params)
        route_list = prepare_routes_data(response["data"])
        logger.info(f"[{self.cname}] =================>>>>>>>>>>> KongDataRoutesAdmin Routes fetched: {response}")

        return {
            'routes': route_list,
            'page': response["page"],
            'total_pages': response['total_pages']
        }

    def count_hosts(self):
        route_list = self.list()

        count = sum([len(r['hosts']) for r in route_list['routes']])

        return count

    def get(self, route_id):
        return self._get(f"{self.path}/{route_id}")

class KongDataPluginsAdmin(KongDataAdmin):
    path = "plugins"

    def __init__(self, kong_id, kong_type="services"):
        self.kong_id = kong_id
        self.kong_type = kong_type

        KongDataAdmin.__init__(self)

    def get_by_id(self):
        return self._get(f"{self.kong_type}/{self.kong_id}/{self.path}")

class KongDataUpstreamsAdmin(KongDataAdmin):
    path = "upstreams"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongDataAdmin.__init__(self)

    def get_targets(self, upstream_id):
        # TODO: handle pagination
        response = self._get(f"{self.path}/{upstream_id}/targets")

        return response.get('data')

    def get_by_name(self, name):
        response = self._get(f"{self.path}/{name}")
        if 'error' in response:
            return None

        return response

class KongDataCertificatesAdmin(KongDataAdmin):
    path = "certificates"

    def __init__(self, owner, cname=None):
        self.owner = owner
        self.cname = cname

        KongDataAdmin.__init__(self)

    def get(self, certificate_id):
        return self._get(f"{self.path}/{certificate_id}")

    def generate_sshkey(self, domain):
        return self._post(f"acme", {'host': domain})
