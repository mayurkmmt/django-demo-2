import io
import itertools
import json
import logging
import re
import socket
import time
import zipfile
from urllib.parse import urlsplit

from django.template.loader import render_to_string
from django_telegrambot.apps import DjangoTelegramBot
from telegram import ParseMode
from telegram.error import RetryAfter
from telegram.ext import CommandHandler, Filters, MessageHandler
from traffic.telegram import BotGroup

from demo2.rest.models import KONG_ROUTE, KongEntityMetadata
from demo2.rest.views import DomainSslConfigRestView
from demo2.utils.domain import dig_domain as dg_domain
from demo2.utils.domain import rr_types
from demo2.utils.telegram import (
    get_cache_strategy,
    get_demo2_black_rules,
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
from demo2.utils.zone import ZoneManagement
from kong.models import (
    KongDataCertificate,
    KongDataPlugin,
    KongDataRoute,
    KongDataService,
    KongDataTarget,
    KongDataUpstream,
)

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

logger = logging.getLogger(__name__)

# Define a few command handlers. These usually take the two arguments bot and
# update. Error handlers also receive the raised TelegramError object in error.

PLUGIN_NAMES = {
    "IP_RESTRICTION": "ip-restriction",
    "demo2_IP_RESTRICTION": "demo2-ip-restriction",
    "demo2_REQUEST_LIMIT": "demo2-request-limit",
    "demo2_CHALLENGE": "demo2-challenge",
    "demo2_REDIRECT": "demo2-redirect",
    "demo2_PROXY_CACHE": "demo2-proxy-cache",
    "demo2_GEOIP": "demo2-geoip",
    "demo2_CUSTOM_ERROR_PAGE": "demo2-custom-error-page",
    "demo2_UPSTREAM_HOST": "demo2-upstream-host",
}


def send_tg(bot, chat_id, message):
    try:
        bot.sendMessage(chat_id, message)
    except RetryAfter as e:
        time.sleep(e.retry_after)
        bot.sendMessage(chat_id, message)


def help(update, context):
    chat_id = update.message.chat_id
    bot = context.bot
    if chat_id == int(BotGroup.demo2_BOT):
        help_info = """
/dl - This command for list your domains ex (/dl abc123.rq0.net)
/di - This command for get information your domain ex (/di Example Domain )
/ci - This command for fetching cert information ex (/ci Example Domain )
/cd - This command for download certs file ex (/cd Example Domain )
/dig - This command for digging domain ex (/dig Example Domain )
/tn-  This command for check port (open/close) - ex (/tn Example Domain  8080)
        """
        bot.sendMessage(chat_id, text=help_info)


def domain_list(update, context):
    chat_id = update.message.chat_id
    if update.message.chat.id == int(BotGroup.demo2_BOT):
        bot = context.bot
        username = update.message.from_user.username
        split_command = update.message.text.split()
        if len(split_command) == 2:
            command, cname = split_command
            kong_domain = KongDataService.objects.filter(tags__icontains=cname).first()
            if kong_domain:
                queryset = KongDataRoute.objects.filter(service_id=kong_domain.id)
                if queryset.exists():
                    domain_list = render_to_string(
                        "telegrambot/domain_list.html",
                        context={"domains": queryset, "cname": cname},
                    )
                    bot.sendMessage(
                        chat_id, text=f"{domain_list}", parse_mode=ParseMode.HTML
                    )
            else:
                bot.sendMessage(chat_id, text=f"CNAME does not have domains")
        else:
            bot.sendMessage(
                chat_id, text=f"Please type your CNAME ex (/dl abc123.rq0.net)"
            )


def domain_info(update, context):
    chat_id = update.message.chat_id
    if chat_id == int(BotGroup.demo2_BOT):
        bot = context.bot
        username = update.message.from_user.username
        split_command = update.message.text.split()
        if len(split_command) == 2:
            command, name = split_command

            urlspt = None
            if re.search(r"(https?:\/\/)|(wss?:\/\/)", name):
                urlspt = urlsplit(name)
                name = urlspt.netloc

            advanced_configuration = {}
            securtiy_setting = {}
            redirect_urls = []
            curl_commands = []

            kong_route = KongDataRoute.objects.filter(hosts__overlap=[name]).first()

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
                securtiy_setting = get_demo2_request_limit(
                    kong_plugins, securtiy_setting
                )
                securtiy_setting = get_demo2_geoip(kong_plugins, securtiy_setting)
                securtiy_setting = get_demo2_ip_restriction(
                    kong_plugins, securtiy_setting
                )
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
                            f"curl \"{redirect_url}\" -H 'Host: {name}' -v -k"
                        )
                else:
                    for upstream_target in upstream_targets:
                        curl_commands.append(
                            f"curl \"{kong_service.protocol}://{upstream_target.target}\" -H 'Host: {name}' -v -k"
                        )

                context = {
                    "status": "Deactivated"
                    if "paused=1" in kong_route.tags
                    else "Running",
                    "kong_route": kong_route,
                    "kong_service": kong_service,
                    "upstream_targets": upstream_targets,
                    "shadow_domains": kong_route.hosts,
                    "advanced_configuration": advanced_configuration,
                    "securtiy_setting": securtiy_setting,
                    "metadata": KongEntityMetadata.get_entity_type_description(
                        KONG_ROUTE, kong_route.id
                    ),
                    "cname_info": ZoneManagement.get_admin_url(kong_route.cname),
                    "curl_commands": curl_commands,
                }

                domain_info = render_to_string(
                    "telegrambot/domain_info.html",
                    context,
                )
                bot.sendMessage(
                    chat_id, text=f"{domain_info}", parse_mode=ParseMode.HTML
                )
            else:
                bot.sendMessage(chat_id, text=f"Domain {name} does not exists.")
        else:
            bot.sendMessage(
                chat_id, text=f"Please type your domain name ex (/di example.com)"
            )


def cert_info(update, context):
    chat_id = update.message.chat_id
    if chat_id == int(BotGroup.demo2_BOT):
        bot = context.bot
        username = update.message.from_user.username
        split_command = update.message.text.split()
        if len(split_command) == 2:
            command, domain = split_command
            kong_domain = KongDataRoute.objects.filter(hosts__overlap=[domain]).first()

            if kong_domain:
                queryset = KongDataCertificate.objects.filter(
                    tags__icontains=kong_domain.cname
                )
                if queryset.exists():
                    cert = queryset.last()
                    cert_info = render_to_string(
                        "telegrambot/cert_info.html",
                        context={"cert": cert, "domain": domain},
                    )
                    bot.sendMessage(
                        chat_id,
                        text=f"{cert_info}@{username}",
                        parse_mode=ParseMode.HTML,
                    )
                else:
                    bot.sendMessage(
                        chat_id,
                        text=f"Domain does not have cert information @{username}",
                        parse_mode=ParseMode.HTML,
                    )
            else:
                bot.sendMessage(
                    chat_id,
                    text=f"Domain does not exist @{username}",
                    parse_mode=ParseMode.HTML,
                )
        else:
            bot.sendMessage(
                chat_id,
                text=f"Please type your domain ex (/ci example.com) @{username}",
            )


def cert_download(update, context):
    chat_id = update.message.chat_id
    if chat_id == int(BotGroup.demo2_BOT):
        bot = context.bot
        username = update.message.from_user.username
        split_command = update.message.text.split()
        if len(split_command) == 2:
            command, domain = split_command
            kong_domain = KongDataRoute.objects.filter(hosts__overlap=[domain]).first()
            if kong_domain:
                queryset = KongDataCertificate.objects.filter(
                    tags__icontains=kong_domain.cname
                )
                redis_certs = DomainSslConfigRestView.fetch_acme_certs(
                    route={"hosts": [domain]}
                )
                if queryset.exists() or redis_certs:
                    fl = io.BytesIO()
                    fl.seek(0)
                    zf = zipfile.ZipFile(fl, "a")

                    if queryset.exists():
                        cert = queryset.last()
                        zf.writestr("%s_fullchain.pem" % cert.pk, cert.cert)
                        zf.writestr("%s_privkey.pem" % cert.pk, cert.key)

                    if redis_certs:
                        for i in range(0, len(redis_certs)):
                            cert_fullchain = redis_certs[i]["cert"]
                            cert_privatekey = redis_certs[i]["key"]
                            zf.writestr(
                                "%s_redis_cert_fullchain.pem" % i, str(cert_fullchain)
                            )
                            zf.writestr(
                                "%s_redis_cert_privkey.pem" % i, str(cert_privatekey)
                            )

                    zf.close()

                    bot.sendDocument(
                        chat_id,
                        document=fl.getvalue(),
                        filename="%s_certs.zip" % domain,
                        caption=f"@{username}",
                    )
                else:
                    bot.sendMessage(
                        chat_id,
                        text=f"Domain does not have cert information @{username}",
                        parse_mode=ParseMode.HTML,
                    )
            else:
                bot.sendMessage(
                    chat_id,
                    text=f"Domain does not exist @{username}",
                    parse_mode=ParseMode.HTML,
                )
        else:
            bot.sendMessage(
                chat_id,
                text=f"Please type your domain ex (/cd example.com) @{username}",
            )


def dig_domain(update, context):
    chat_id = update.message.chat_id
    if chat_id == int(BotGroup.demo2_BOT):
        bot = context.bot
        username = update.message.from_user.username
        split_command = update.message.text.split()
        if len(split_command) == 2:
            command, domain = split_command
            obj = dg_domain(domain)
            if "Answer" in obj:
                answers = []
                for i in range(len(obj["Answer"])):
                    ans = obj["Answer"][i]
                    ans["type"] = rr_types[ans["type"]]
                    answers.append(ans)
                dig_info = render_to_string(
                    "telegrambot/domain_dig.html",
                    context={"domain": domain, "answers": answers},
                )
                bot.sendMessage(chat_id, text=f"{dig_info}", parse_mode=ParseMode.HTML)
            else:
                bot.sendMessage(chat_id, text=f"Domain {domain} doesn't have answer")
        else:
            bot.sendMessage(
                chat_id, text=f"Please type your domain name ex (/dig example.com)"
            )


def telnet(update, context):
    chat_id = update.message.chat_id
    if chat_id == int(BotGroup.demo2_BOT):
        bot = context.bot
        split_command = update.message.text.split()
        if len(split_command) == 3:
            command, host, port = split_command
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                host_ip = socket.gethostbyname(host)
            except socket.gaierror:
                bot.sendMessage(chat_id, text="Cannot resolving the host")
                return None
            try:
                sock.connect((host_ip, port))
                bot.sendMessage(chat_id, text=f"Port {port} of {host} is open")
            except socket.timeout:
                bot.sendMessage(chat_id, text=f"[Timeout] port {port} of host is close")
        else:
            bot.sendMessage(
                chat_id, text="Please type host and port ex (/tn example.com 8080)"
            )


def error(update, context):
    logger.warning('Update "%s" caused error "%s"', update, error)
    raise context.error


def main():
    logger.info("Loading handlers for telegram bot")

    # Default dispatcher (this is related to the first bot in settings.DJANGO_TELEGRAMBOT['BOTS'])
    dp = DjangoTelegramBot.dispatcher

    # on different commands - answer in Telegram
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("dl", domain_list))
    dp.add_handler(CommandHandler("di", domain_info))
    dp.add_handler(CommandHandler("ci", cert_info))
    dp.add_handler(CommandHandler("cd", cert_download))
    dp.add_handler(CommandHandler("dig", dig_domain))
    dp.add_handler(CommandHandler("tn", telnet))

    # log all errors
    dp.add_error_handler(error)
