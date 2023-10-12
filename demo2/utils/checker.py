import logging
import re
import socket
import ssl
import subprocess
from urllib.parse import urlparse

import dns.resolver
import requests
from django.conf import settings
from requests.exceptions import ConnectTimeout, SSLError

from demo2.utils import request_wrapper
from kong.models import (
    KongDataPlugin,
    KongDataService,
    KongDataTarget,
    KongDataUpstream,
)


class Checker(object):
    def check(self, route, steps, continue_on_false=False):
        status = {step: (False, "") for step in steps}
        for step in steps:
            check_method = getattr(self, step)
            try:
                checkrs = check_method(route)
                checkmsg = "OK" if checkrs else "Failed"
            except Exception as e:
                checkrs = False
                logging.info(e)
                checkmsg = str(e)

            status[step] = (checkrs, checkmsg)

            if checkrs == False and continue_on_false == False:
                logging.info("failed on %s" % step)
                break

        return status

    def init(self, route):
        tags = {}
        for item in route.tags:
            key, value = item.replace('"', "").split("=")
            tags[key] = value
        return all([tags["cname"], ".".join([route.name, tags["cname"]])])

    def dns_cdn_challenge(self, domain):
        domain_name = domain.name
        if domain_name.count(".") == 1:
            root_domain = domain_name
        else:
            root_domain = ".".join(domain_name.split(".")[1:])

        try:
            a = dns.resolver.query(
                "_cdn-challenge." + root_domain, rdtype=dns.rdatatype.RdataType.TXT
            )
        except dns.exception.DNSException as e:
            raise RuntimeError("DNS query failed")

        res = "%s" % a.response

        if re.search(r'TXT\s+"%s"' % settings.DNSSERVER_NEEDLE, res) != None:
            return True

        return False

    def cname_query(self, domain):
        return all([len(dns.resolver.query(domain.cname)) > 0])

    def cname_visit(self, domain):
        try:
            r = requests.get("http://%s/" % domain.cname, timeout=2)
        except requests.exceptions.RequestException as e:
            raise RuntimeError("CName visit failed")

        if r.status_code != 200 or r.headers["server"].find("sy_shiao") < 0:
            raise RuntimeError("CName visit failed")

        return True

    def domain_setup(self, domain):
        return all(
            [
                self.init(domain),
                self.cname_visit(domain),
                self.source_cname(domain),
            ]
        )

    def source_cname(self, route):
        domain = route.hosts[0]
        try:
            a = dns.resolver.query(domain)
        except dns.exception.DNSException as e:
            raise RuntimeError("DNS query failed")

        res = "%s" % a.response
        if re.search(r"CNAME.+%s" % route.cname, res) != None:
            return True
        elif re.search(r"CNAME.+%s" % route.domain_cname, res) != None:
            return True
        elif domain.count(".") == 1 and a.rdtype == dns.rdatatype.A:  # Naked domain
            try:
                ip = a.response.answer[0][0].address
                v = requests.get("http://%s/ok" % ip)
                if v.text == "OK":
                    return True
            except Exception:
                logging.warn("Try nake domain check failed")

        raise RuntimeError("CName not found")

    def source_visit_https(self, route, config=None):
        domain, protocol, url, hostname, port = self.get_context(route)
        try:
            cmnd = [
                "curl",
                "-s",
                "--max-time",
                "5",
                "-I",
                "https://%s/" % domain,
                "--resolve",
                "%s:%d:%s" % (domain, port, hostname),
                "-k",
            ]
            tryhttps = subprocess.run(cmnd, capture_output=True)

            if tryhttps.returncode > 0:
                cmd = [
                    "curl",
                    "--max-time",
                    "5",
                    "%s://%s/" % (protocol, domain),
                    "--resolve",
                    "%s:%d:%s" % (domain, port, hostname),
                    "-v",
                    "-k",
                ]
                checkhttps = subprocess.run(cmd, capture_output=True)
                err = checkhttps.stderr.decode("utf-8")
                re_ssl_err = re.search(r"SSL: (?P<message>.*)", err)
                re_ssl_cert_problem = re.search(
                    r"SSL certificate problem: (?P<message>.*)", err
                )
                error_message = ""
                if re_ssl_err:
                    error_message = f"SSL: {re_ssl_err.group('message')}"
                elif re_ssl_cert_problem:
                    error_message = f"SSL certificate problem: {re_ssl_cert_problem.group('message')}"
                raise RuntimeError(
                    "Source https checked failed: %s %s"
                    % (tryhttps.returncode, error_message)
                )

        except SSLError as e:
            logging.info(e)
            raise RuntimeError("SSL Error2")
        except ConnectTimeout as e:
            logging.info(e)
            raise RuntimeError("Connect Timeout")
        except ConnectionError as e:
            logging.info(e)
            raise RuntimeError("Connect Error")
        except Exception as e:
            logging.info(e)
            raise e

        return True

    #         return all([
    #             r.status_code >= 200 and r.status_code < 500,
    #             len(r.content.decode("UTF-8").strip()) > 10
    #             ])

    def get_context(self, route):
        domain = route.hosts[0]
        service = route.get_service()
        protocol = "http"
        port = 80
        if "demo2-redirect" in service.host:
            plugin_name, plugin_id = service.host.split(".")
            plugin = KongDataPlugin.objects.get(name=plugin_name, id=plugin_id)
            url = plugin.config.get("redirect_url")
        else:
            upstream = KongDataUpstream.objects.get(name=route.name)
            target = KongDataTarget.objects.filter(upstream_id=upstream.id).first()
            target = target.target
            url = f"{service.protocol}://{target}"
        up = urlparse(url)
        port = up.port
        if port is None:
            port = 443 if protocol == "https" else 80
        return domain, protocol, url, up.hostname, port

    def source_visit(self, route):
        from demo2.rest.views import DomainSslConfigRestView

        domain, protocol, url, hostname, port = self.get_context(route)
        try:
            if protocol == "https":
                certs = DomainSslConfigRestView.fetch_acme_certs(route.__dict__)
                if len(certs):
                    raise RuntimeError("HTTPS is required")

                return self.source_visit_https(route)
            r = requests.get(
                url,
                headers={"Host": "%s" % domain},
                allow_redirects=False,
                timeout=2,
                verify=False,
            )

            if r.status_code == 301 or r.status_code == 302:
                if r.headers["Location"].startswith("https://%s" % domain):
                    checkRs = self.source_visit_https(route)
                    return checkRs
                elif r.headers["Location"].startswith("http"):
                    r = requests.get(r.headers["Location"], timeout=2, verify=False)
                else:
                    url2 = "%s%s" % (url, r.headers["Location"])
                    r = requests.get(
                        url2,
                        headers={"Host": "%s" % domain},
                        allow_redirects=True,
                        timeout=2,
                        verify=False,
                    )
        except SSLError as e:
            logging.info(e)
            raise RuntimeError("SSL Error")
        except ConnectTimeout as e:
            logging.info(e)
            raise RuntimeError("Connect Timeout")
        except ConnectionError as e:
            logging.info(e)
            raise RuntimeError("Connect Error")
        except Exception as e:
            logging.info(e)
            raise e

        return True

    def site_visit(self, route):
        service = route.get_service()
        scheme = service.protocol
        domain = route.hosts[0]

        check_url = "%s://%s/" % (scheme, domain)

        try:
            _r = requests.get(check_url, verify=ssl.CERT_NONE, timeout=5)
        except SSLError as e:
            raise RuntimeError("SSL Error3")
        except Exception as e:
            raise e  # RuntimeError('Check URL error')

        return True

    def site_visit_v6(self, route):
        service = route.get_service()
        scheme = service.protocol
        domain = route.hosts[0]

        check_url = "%s://%s/" % (scheme, domain)

        try:
            _r = request_wrapper.get(
                check_url, verify=ssl.CERT_NONE, timeout=5, family=socket.AF_INET6
            )
        except SSLError as e:
            raise RuntimeError("SSL Error3")
        except Exception as e:
            raise e  # RuntimeError('Check URL error')

        return True

    def source_setup(self, domain):
        return all(
            [
                self.source_cname(domain),
                self.source_visit(domain),
            ]
        )

    def ssl_config(self, domain):
        return all(
            [
                self.sslConfigEnabled,
                # TODO: Add more
            ]
        )

    def ssl_visit(self, route):
        domain = route.hosts[0]
        try:
            r = requests.get("https://%s/" % domain, verify=ssl.CERT_NONE, timeout=2)
        except SSLError as e:
            raise RuntimeError("SSL Error")
        except Exception as e:
            raise e  # RuntimeError('Check URL error')

        return True

    def ssl_setup(self, domain):
        return all(
            [
                self.ssl_config(domain),
                self.ssl_visit(domain),
            ]
        )
