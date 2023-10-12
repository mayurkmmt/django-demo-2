import time

from celery.utils.log import get_task_logger
from celery_progress.backend import ProgressRecorder
from django.template.loader import render_to_string

from config.celery_app import app
from demo2.rest.models import KONG_ROUTE, KongEntityMetadata
from demo2.utils.redis_notification import send_user_fcm_notification
from demo2.utils.telegram import (
    get_cache_strategy,
    get_demo2_black_rules,
    get_demo2_captcha,
    get_demo2_challenge,
    get_demo2_crowdsec_captcha,
    get_demo2_custom_error_page,
    get_demo2_geoip,
    get_demo2_ip_restriction,
    get_demo2_redirect_url,
    get_demo2_request_limit,
    get_demo2_sec_link,
    get_demo2_upstream_host,
    get_response_transformer,
)
from kong.models import (
    KongDataCertificate,
    KongDataPlugin,
    KongDataRoute,
    KongDataService,
    KongDataTarget,
    KongDataUpstream,
)

logging = get_task_logger(__name__)


@app.task(name="domain.fetch_domain_info")
def fetch_domain_info(hostname, cname, shadow):
    try:
        context = {}
        advanced_configuration = {}
        securtiy_setting = {}
        redirect_urls = []
        curl_commands = []

        kong_route = KongDataRoute.objects.filter(hosts__overlap=[shadow]).first()

        if kong_route:
            kong_service = KongDataService.objects.filter(
                id=kong_route.service_id
            ).first()

            upstream_targets = []
            kong_plugins = KongDataPlugin.objects.filter(
                service_id=kong_route.service_id
            )

            advanced_configuration = get_cache_strategy(
                kong_plugins, advanced_configuration
            )
            advanced_configuration = get_demo2_upstream_host(
                kong_plugins, advanced_configuration
            )
            advanced_configuration = get_response_transformer(
                kong_plugins, advanced_configuration
            )

            securtiy_setting = get_demo2_challenge(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_request_limit(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_captcha(kong_plugins, securtiy_setting)

            shield_detection = False
            if securtiy_setting["shield_detection"] == "Use JS Protection":
                shield_detection = True

            rate_limiting = False
            if (
                "rate_limiting" in securtiy_setting
                and securtiy_setting["rate_limiting"]["enabled"]
            ):
                rate_limiting = True

            captcha = False
            if "captcha" in securtiy_setting and securtiy_setting["captcha"]["enabled"]:
                captcha = True

            add_everyone_in_cc_alert = False
            if not shield_detection or not rate_limiting or not captcha:
                add_everyone_in_cc_alert = True

            securtiy_setting = get_demo2_challenge(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_request_limit(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_geoip(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_ip_restriction(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_custom_error_page(
                kong_plugins, securtiy_setting
            )
            securtiy_setting = get_demo2_crowdsec_captcha(
                kong_plugins, securtiy_setting
            )
            securtiy_setting = get_demo2_black_rules(kong_plugins, securtiy_setting)
            securtiy_setting = get_demo2_sec_link(kong_plugins, securtiy_setting)

            kong_upstream = KongDataUpstream.objects.filter(
                name=kong_route.name
            ).first()
            if kong_upstream:
                upstream_targets = KongDataTarget.objects.filter(
                    upstream_id=kong_upstream.id
                )

            redirect_urls = get_demo2_redirect_url(kong_plugins, redirect_urls)
            if len(redirect_urls) > 0:
                for redirect_url in redirect_urls:
                    curl_commands.append(
                        f"curl \"{redirect_url}\" -H 'Host: {shadow}' -v -k"
                    )
            else:
                for upstream_target in upstream_targets:
                    curl_commands.append(
                        f"curl \"{kong_service.protocol}://{upstream_target.target}\" -H 'Host: {kong_service.host}' -v -k"
                    )

            try:
                status = "Deactivated" if "paused=1" in kong_route.tags else "Running"
            except Exception as e:
                status = "Running"

            context = {
                "status": status,
                "kong_route": kong_route,
                "upstream_targets": upstream_targets,
                "shadow_domains": kong_route.hosts,
                "advanced_configuration": advanced_configuration,
                "securtiy_setting": securtiy_setting,
                "metadata": KongEntityMetadata.get_entity_type_description(
                    KONG_ROUTE, kong_route.id
                ),
                "curl_commands": curl_commands,
                "add_everyone_in_cc_alert": add_everyone_in_cc_alert,
            }

        domain_info = render_to_string(
            "telegrambot/domain_info.html",
            context,
        )

        return domain_info

    except Exception as e:
        logging.error(
            f"fetch_domain_info error to get the domain by cname: {cname} - {e}"
        )

    return ""


@app.task(name="domain.batch_actions.clear_cache", bind=True)
def clear_cache(self, owner, cname, ids, user_id=None):
    from kong.gateway import KongServicesAdmin

    progress_recorder = ProgressRecorder(self)

    result = 0
    total = len(ids)

    for service_id in ids:
        ks = KongServicesAdmin(owner, cname=cname)
        service = ks.get(service_id)

        progress_recorder.set_progress(
            result, total, f"Clearing cache for {service['host']} {result}/{total}"
        )

        plugins = ks.get_plugins(service_id)
        plugin_name_to_id = {p["name"]: p["id"] for p in plugins}

        cache_plugin = {}
        for p in plugins:
            if p["name"] == "demo2-proxy-cache":
                cache_plugin = p
                break

        if cache_plugin:
            cache_plugin["config"]["cache_version"] = int(time.time())
            ks.update_or_create_plugin(
                service_id, cache_plugin, plugin_name_to_id.get("demo2-proxy-cache")
            )

        result += 1

    if user_id:
        send_user_fcm_notification(user_id, "clear_cache")
    return {"description": f"Done clearing cache ({total}/{total})"}


@app.task(name="domain.batch_actions.force_https", bind=True)
def force_https(self, owner, cname, routeIds, enable, user_id=None):
    from kong.gateway import KongRoutesAdmin

    kr = KongRoutesAdmin(owner, cname=cname)

    progress_recorder = ProgressRecorder(self)

    result = 0
    total = len(routeIds)

    for route_id in routeIds:
        route = kr.get(route_id)
        kr.force_https(route_id, enable)

        msg = f"Enabling force https for {route['hosts'][0]}  {result}/{total}"
        if not enable:
            msg = f"Disabling force https for {route['hosts'][0]}  {result}/{total}"

        progress_recorder.set_progress(result, total, msg)
        result += 1

    if user_id:
        if not enable:
            send_user_fcm_notification(user_id, "disable_force_https")
        else:
            send_user_fcm_notification(user_id, "enable_force_https")
    return {"description": f"Done force https ({total}/{total})"}


@app.task(name="domain.enable_https", bind=True)
def enable_https(self, owner, cname, route_id, user_id=None):
    from kong.gateway import KongCertificatesAdmin, KongRoutesAdmin

    kr = KongRoutesAdmin(owner, cname=cname)
    ks = KongCertificatesAdmin(owner, cname)
    try:
        route = kr.get(route_id)
    except:
        return

    for domain in route["hosts"]:
        try:
            ks.generate_sshkey(domain)
        except Exception as e:
            logging.error(
                f"Failed to generate certificate for {domain}. Exception: {e}"
            )
            continue

    if user_id:
        send_user_fcm_notification(user_id, "enable_https")
    return {"description": f"Done enable https for " + ",".join(route["hosts"])}


@app.task(name="domain.add_kong_plugin_to_domain")
def add_kong_plugin_to_domain(hostname, cname, pluginName):
    from kong.gateway import KongServicesAdmin

    try:
        logging.info(
            f"add_kong_plugin_to_domain hostname: {hostname}, cname: {cname}, pluginName: {pluginName}"
        )

        # get service info
        ks = KongServicesAdmin("", cname=cname)
        services = ks.get_by_cname()
        service = {}
        if "data" in services and services["data"]:
            for s in services["data"]:
                if s["host"] == hostname.replace(".", "-"):
                    service = s

        logging.info(f" ====>>>>>>> add_kong_plugin_to_domain service: {service}")

        if service:
            logging.info(
                f" ====>>>>>>> add_kong_plugin_to_domain service_id: {service['id']}"
            )
            if pluginName == "demo2-challenge":
                plugins = ks.get_plugins(service["id"])
                plugin_name_to_id = {p["name"]: p["id"] for p in plugins}

                plugin_data = {
                    "config": {
                        "agents": {"checklist": [], "whitelist": []},
                        "challenge": "js",
                        "white_uris": [],
                    },
                    "enabled": True,
                    "name": pluginName,
                }
                ks.update_or_create_plugin(
                    service["id"], plugin_data, plugin_name_to_id.get("demo2-challenge")
                )

        return True

    except Exception as exc:
        logging.error(f"add_kong_plugin_to_domain ERROR: {cname} - {str(exc)}")
        return False
