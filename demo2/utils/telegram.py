def get_cache_strategy(kong_plugins, advanced_configuration):
    cache_strategy = kong_plugins.filter(name="demo2-proxy-cache").first()

    if cache_strategy:
        cookie_bypass_rules = []
        path_bypass_rules = []
        query_bypass_rules = []

        advanced_configuration["cache_strategy"] = {}
        advanced_configuration["cache_strategy"]["request"] = {}
        advanced_configuration["cache_strategy"]["response"] = {}

        advanced_configuration["cache_strategy"]["enabled"] = cache_strategy.enabled

        for rule in cache_strategy.config["bypass_rules"]:
            if "COOKIE" in rule:
                rule = rule.split("COOKIE:")[1]
                cookie_bypass_rules.append(rule)
            elif "PATH" in rule:
                rule = rule.split("PATH:")[1]
                path_bypass_rules.append(rule)
            elif "QUERY" in rule:
                rule = rule.split("QUERY:")[1]
                query_bypass_rules.append(rule)
        advanced_configuration["cache_strategy"]["request"][
            "cookie_bypass_rules"
        ] = cookie_bypass_rules
        advanced_configuration["cache_strategy"]["request"][
            "path_bypass_rules"
        ] = path_bypass_rules
        advanced_configuration["cache_strategy"]["request"][
            "query_bypass_rules"
        ] = query_bypass_rules
        advanced_configuration["cache_strategy"]["request"][
            "request_method"
        ] = cache_strategy.config["request_method"]
        advanced_configuration["cache_strategy"]["response"][
            "response_code"
        ] = cache_strategy.config["response_code"]
        advanced_configuration["cache_strategy"]["response"][
            "content_type"
        ] = cache_strategy.config["content_type"]
        advanced_configuration["cache_strategy"][
            "cache_control"
        ] = cache_strategy.config["cache_control"]

    return advanced_configuration


def get_demo2_upstream_host(kong_plugins, advanced_configuration):
    upstream_host = kong_plugins.filter(name="demo2-upstream-host").first()
    if upstream_host:
        advanced_configuration["proxy_host"] = {}
        advanced_configuration["proxy_host"]["enabled"] = upstream_host.enabled
        advanced_configuration["proxy_host"]["domain"] = upstream_host.config[
            "hostname"
        ]
    return advanced_configuration


def get_response_transformer(kong_plugins, advanced_configuration):
    response_transformer = kong_plugins.filter(name="response-transformer").first()
    if response_transformer:
        advanced_configuration["custom_header"] = {}
        advanced_configuration["custom_header"][
            "enabled"
        ] = response_transformer.enabled
        if (
            response_transformer.config
            and "add" in response_transformer.config
            and "headers" in response_transformer.config["add"]
        ):
            advanced_configuration["custom_header"][
                "custom_header_list"
            ] = response_transformer.config["add"]["headers"]
        else:
            advanced_configuration["custom_header"]["custom_header_list"] = []
    return advanced_configuration


def get_demo2_crowdsec_captcha(kong_plugins, securtiy_setting):
    crowdsec_captcha = kong_plugins.filter(name="demo2-crowdsec-captcha").first()
    if crowdsec_captcha:
        securtiy_setting["captcha_security"] = {}
        securtiy_setting["captcha_security"]["enabled"] = crowdsec_captcha.enabled
        if crowdsec_captcha.config:
            securtiy_setting["captcha_security"]["findtime"] = crowdsec_captcha.config[
                "findtime"
            ]
            securtiy_setting["captcha_security"]["maxretry"] = crowdsec_captcha.config[
                "maxretry"
            ]
            securtiy_setting["captcha_security"]["bantime"] = crowdsec_captcha.config[
                "bantime"
            ]
    return securtiy_setting


def get_demo2_challenge(kong_plugins, securtiy_setting):
    shield_detection = kong_plugins.filter(name="demo2-challenge").first()
    securtiy_setting["shield_detection"] = (
        "Use JS Protection"
        if (shield_detection and shield_detection.enabled)
        else "Disable Protection"
    )
    return securtiy_setting


def get_demo2_request_limit(kong_plugins, securtiy_setting):
    request_limiting = kong_plugins.filter(name="demo2-request-limit").first()
    if request_limiting:
        securtiy_setting["rate_limiting"] = {}
        securtiy_setting["rate_limiting"]["enabled"] = request_limiting.enabled
        securtiy_setting["rate_limiting"]["time_interval"] = request_limiting.config[
            "findtime"
        ]
        securtiy_setting["rate_limiting"][
            "frequency_of_visit"
        ] = request_limiting.config["maxretry"]
        securtiy_setting["rate_limiting"]["ban_time"] = request_limiting.config[
            "bantime"
        ]
        securtiy_setting["rate_limiting"]["protection_path"] = request_limiting.config[
            "banpath"
        ]
        securtiy_setting["rate_limiting"][
            "dynamic_content_only"
        ] = request_limiting.config["only_dynamic"]
    return securtiy_setting


def get_demo2_geoip(kong_plugins, securtiy_setting):
    demo2_geoip = kong_plugins.filter(name="demo2-geoip").first()
    if demo2_geoip:
        securtiy_setting["geo_country_access"] = {}
        securtiy_setting["geo_country_access"]["enabled"] = demo2_geoip.enabled
        securtiy_setting["geo_country_access"]["mode"] = demo2_geoip.config["mode"]
        securtiy_setting["geo_country_access"][
            "blacklist_countries"
        ] = demo2_geoip.config["blacklist_countries"]
    return securtiy_setting


def get_demo2_captcha(kong_plugins, securtiy_setting):
    demo2_captcha = kong_plugins.filter(name="demo2-crowdsec-captcha").first()
    if demo2_captcha:
        securtiy_setting["captcha"] = {}
        securtiy_setting["captcha"]["enabled"] = demo2_captcha.enabled
        securtiy_setting["captcha"]["findtime"] = demo2_captcha.config["findtime"]
        securtiy_setting["captcha"]["maxretry"] = demo2_captcha.config["maxretry"]
        securtiy_setting["captcha"]["bantime"] = demo2_captcha.config["bantime"]
    return securtiy_setting


def get_demo2_ip_restriction(kong_plugins, securtiy_setting):
    ip_restriction = kong_plugins.filter(name="demo2-ip-restriction").first()
    if ip_restriction:
        securtiy_setting["ip_restriction"] = {}
        securtiy_setting["ip_restriction"]["enabled"] = ip_restriction.enabled
        securtiy_setting["ip_restriction"]["allow_spiders"] = ip_restriction.config[
            "allow_spiders"
        ]
        securtiy_setting["ip_restriction"]["allow"] = ip_restriction.config["allow"]
        securtiy_setting["ip_restriction"]["deny"] = ip_restriction.config["deny"]
    return securtiy_setting


def get_demo2_custom_error_page(kong_plugins, securtiy_setting):
    custom_error_page = kong_plugins.filter(name="demo2-custom-error-page").first()
    if custom_error_page:
        securtiy_setting["custom_error_pages"] = {}
        securtiy_setting["custom_error_pages"]["enabled"] = custom_error_page.enabled
        securtiy_setting["custom_error_pages"]["config"] = custom_error_page.config
    return securtiy_setting


def get_demo2_black_rules(kong_plugins, securtiy_setting):
    black_rules = kong_plugins.filter(name="demo2-blackrules").first()
    if black_rules:
        rules = black_rules.config["rules"]["rule"]
        rules = (
            rules.replace("return ", "")
            .replace("{", "[")
            .replace("}", "]")
            .replace("'", '"')
        )
        securtiy_setting["black_rules"] = {}
        securtiy_setting["black_rules"]["enabled"] = black_rules.enabled
        securtiy_setting["black_rules"]["action"] = black_rules.config["action"]
        securtiy_setting["black_rules"]["bantime"] = black_rules.config["bantime"]
        securtiy_setting["black_rules"]["rules"] = rules
    return securtiy_setting


def get_demo2_sec_link(kong_plugins, securtiy_setting):
    sec_link = kong_plugins.filter(name="demo2-seclink").first()
    if sec_link:
        securtiy_setting["sec_link"] = {}
        securtiy_setting["sec_link"]["enable_sec_redirect"] = sec_link.config[
            "enable_sec_redirect"
        ]
        securtiy_setting["sec_link"]["api_secret"] = sec_link.config["api_secret"]
        securtiy_setting["sec_link"]["sleep_seconds"] = sec_link.config["sleep_seconds"]
        securtiy_setting["sec_link"]["expire_seconds"] = sec_link.config[
            "expire_seconds"
        ]
    return securtiy_setting


def get_demo2_redirect_url(kong_plugins, redirect_urls):
    for redirect_url in kong_plugins.filter(name="demo2-redirect").all():
        if redirect_url.config and "redirect_url" in redirect_url.config:
            redirect_urls.append(redirect_url.config["redirect_url"])
    return redirect_urls
