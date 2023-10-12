import uuid

from django.contrib.postgres.fields import ArrayField
from django.db import models


class KongDataService(models.Model):
    # -----------------------+--------------------------+-----------+----------+---------
    #  id                    | uuid                     |           | not null |
    #  created_at            | timestamp with time zone |           |          |
    #  updated_at            | timestamp with time zone |           |          |
    #  name                  | text                     |           |          |
    #  retries               | bigint                   |           |          |
    #  protocol              | text                     |           |          |
    #  host                  | text                     |           |          |
    #  port                  | bigint                   |           |          |
    #  path                  | text                     |           |          |
    #  connect_timeout       | bigint                   |           |          |
    #  write_timeout         | bigint                   |           |          |
    #  read_timeout          | bigint                   |           |          |
    #  tags                  | text[]                   |           |          |
    #  client_certificate_id | uuid                     |           |          |
    #  tls_verify            | boolean                  |           |          |
    #  tls_verify_depth      | smallint                 |           |          |
    #  ca_certificates       | uuid[]                   |           |          |
    #  ws_id                 | uuid                     |           |          |
    #  enabled               | boolean                  |           |          | true
    # Indexes:
    #     "services_pkey" PRIMARY KEY, btree (id)
    #     "services_fkey_client_certificate" btree (client_certificate_id)
    #     "services_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "services_tags_idx" gin (tags)
    #     "services_ws_id_name_unique" UNIQUE CONSTRAINT, btree (ws_id, name)
    # Foreign-key constraints:
    #     "services_client_certificate_id_fkey" FOREIGN KEY (client_certificate_id, ws_id) REFERENCES certificates(id, ws_id)
    #     "services_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Referenced by:
    #     TABLE "oauth2_authorization_codes" CONSTRAINT "oauth2_authorization_codes_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id) ON DELETE CASCADE
    #     TABLE "oauth2_tokens" CONSTRAINT "oauth2_tokens_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id) ON DELETE CASCADE
    #     TABLE "plugins" CONSTRAINT "plugins_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id) ON DELETE CASCADE
    #     TABLE "routes" CONSTRAINT "routes_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id)
    # Triggers:
    #     services_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON services FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField(blank=True, null=True)
    retries = models.BigIntegerField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    host = models.TextField(blank=True, null=True)
    port = models.BigIntegerField(blank=True, null=True)
    path = models.TextField(blank=True, null=True)
    connect_timeout = models.BigIntegerField(blank=True, null=True)
    write_timeout = models.BigIntegerField(blank=True, null=True)
    read_timeout = models.BigIntegerField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    client_certificate_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    tls_verify = models.BigIntegerField(blank=True, null=True)
    tls_verify_depth = models.SmallIntegerField(blank=True, null=True)
    ca_certificates = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        app_label = "demo2_kong"
        db_table = "services"

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def tags_to_dict(self):
        tags = {}
        for tag in self.tags:
            key, value = tag.replace('"', "").split("=")
            tags[key] = value
        return tags

    @property
    def cname(self):
        tags = self.tags_to_dict()
        return tags["cname"]


class KongDataRoute(models.Model):
    # -----------------------+--------------------------+-----------+----------+---------
    #  id                         | uuid                     |           | not null |
    #  created_at                 | timestamp with time zone |           |          |
    #  updated_at                 | timestamp with time zone |           |          |
    #  name                       | text                     |           |          |
    #  service_id                 | uuid                     |           |          |
    #  protocols                  | text[]                   |           |          |
    #  methods                    | text[]                   |           |          |
    #  hosts                      | text[]                   |           |          |
    #  paths                      | text[]                   |           |          |
    #  snis                       | text[]                   |           |          |
    #  sources                    | jsonb[]                  |           |          |
    #  destinations               | jsonb[]                  |           |          |
    #  regex_priority             | bigint                   |           |          |
    #  strip_path                 | boolean                  |           |          |
    #  preserve_host              | boolean                  |           |          |
    #  tags                       | text[]                   |           |          |
    #  https_redirect_status_code | integer                  |           |          |
    #  headers                    | jsonb                    |           |          |
    #  path_handling              | text                     |           |          | 'v0'::text
    #  ws_id                      | uuid                     |           |          |
    #  request_buffering          | boolean                  |           |          |
    #  response_buffering         | boolean                  |           |          |
    # Indexes:
    #     "routes_pkey" PRIMARY KEY, btree (id)
    #     "routes_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "routes_service_id_idx" btree (service_id)
    #     "routes_tags_idx" gin (tags)
    #     "routes_ws_id_name_unique" UNIQUE CONSTRAINT, btree (ws_id, name)
    # Foreign-key constraints:
    #     "routes_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id)
    #     "routes_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Referenced by:
    #     TABLE "plugins" CONSTRAINT "plugins_route_id_fkey" FOREIGN KEY (route_id, ws_id) REFERENCES routes(id, ws_id) ON DELETE CASCADE
    # Triggers:
    #     routes_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON routes FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField(blank=True, null=True)
    service_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    protocols = ArrayField(models.TextField(), blank=True, null=True)
    methods = ArrayField(models.TextField(), blank=True, null=True)
    hosts = ArrayField(models.TextField(), blank=True, null=True)
    paths = ArrayField(models.TextField(), blank=True, null=True)
    snis = ArrayField(models.TextField(), blank=True, null=True)
    sources = models.JSONField(blank=True, null=True)
    destinations = models.JSONField(blank=True, null=True)
    regex_priority = models.BigIntegerField(blank=True, null=True)
    strip_path = models.BooleanField(default=False)
    preserve_host = models.BooleanField(default=False)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    https_redirect_status_code = models.IntegerField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)
    path_handling = models.TextField(blank=True, null=True)
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_buffering = models.BooleanField(default=False)
    response_buffering = models.BooleanField(default=False)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "kong_entity_metadatas"
        app_label = "demo2_kong"
        db_table = "routes"

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def get_service(self):
        return KongDataService.objects.get(id=self.service_id)

    def get_upstream(self):
        return KongDataUpstream.objects.get(name=self.name)

    def is_force_https(self):
        return self.protocols == ["https"]

    def tags_to_dict(self):
        tag_dict = {}
        if self.tags:
            for tag in self.tags:
                key, value = tag.replace('"', "").split("=")
                tag_dict[key] = value
        return tag_dict

    @property
    def cname(self):
        tags = self.tags_to_dict()
        if "cname" in tags:
            return tags["cname"]
        return ""

    @property
    def domain_cname(self):
        tags = self.tags_to_dict()
        return f"{self.name}.{tags['cname']}"


class KongDataPlugin(models.Model):
    # -------------+--------------------------+-----------+----------+-------------------------------------------------
    #  id          | uuid                     |           | not null |
    #  created_at  | timestamp with time zone |           |          | (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
    #  name        | text                     |           | not null |
    #  consumer_id | uuid                     |           |          |
    #  service_id  | uuid                     |           |          |
    #  route_id    | uuid                     |           |          |
    #  config      | jsonb                    |           | not null |
    #  enabled     | boolean                  |           | not null |
    #  cache_key   | text                     |           |          |
    #  protocols   | text[]                   |           |          |
    #  tags        | text[]                   |           |          |
    #  ws_id       | uuid                     |           |          |
    # Indexes:
    #     "plugins_pkey" PRIMARY KEY, btree (id)
    #     "plugins_cache_key_key" UNIQUE CONSTRAINT, btree (cache_key)
    #     "plugins_consumer_id_idx" btree (consumer_id)
    #     "plugins_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "plugins_name_idx" btree (name)
    #     "plugins_route_id_idx" btree (route_id)
    #     "plugins_service_id_idx" btree (service_id)
    #     "plugins_tags_idx" gin (tags)
    # Foreign-key constraints:
    #     "plugins_consumer_id_fkey" FOREIGN KEY (consumer_id, ws_id) REFERENCES consumers(id, ws_id) ON DELETE CASCADE
    #     "plugins_route_id_fkey" FOREIGN KEY (route_id, ws_id) REFERENCES routes(id, ws_id) ON DELETE CASCADE
    #     "plugins_service_id_fkey" FOREIGN KEY (service_id, ws_id) REFERENCES services(id, ws_id) ON DELETE CASCADE
    #     "plugins_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Triggers:
    #     plugins_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON plugins FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField(blank=False, null=False)
    consumer_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    route_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    config = models.JSONField(blank=True, null=True)
    enabled = models.BooleanField(default=False)
    cache_key = models.TextField(blank=True, null=True)
    protocols = ArrayField(models.TextField(), blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        app_label = "demo2_kong"
        db_table = "plugins"

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)


class KongDataUpstream(models.Model):
    # -----------------------+--------------------------+-----------+----------+-------------------------------------------------
    #  id                    | uuid                     |           | not null |
    #  created_at            | timestamp with time zone |           |          | (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'::text)
    #  name                  | text                     |           |          |
    #  hash_on               | text                     |           |          |
    #  hash_fallback         | text                     |           |          |
    #  hash_on_header        | text                     |           |          |
    #  hash_fallback_header  | text                     |           |          |
    #  hash_on_cookie        | text                     |           |          |
    #  hash_on_cookie_path   | text                     |           |          |
    #  slots                 | integer                  |           | not null |
    #  healthchecks          | jsonb                    |           |          |
    #  tags                  | text[]                   |           |          |
    #  algorithm             | text                     |           |          |
    #  host_header           | text                     |           |          |
    #  client_certificate_id | uuid                     |           |          |
    #  ws_id                 | uuid                     |           |          |
    # Indexes:
    #     "upstreams_pkey" PRIMARY KEY, btree (id)
    #     "upstreams_fkey_client_certificate" btree (client_certificate_id)
    #     "upstreams_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "upstreams_tags_idx" gin (tags)
    #     "upstreams_ws_id_name_unique" UNIQUE CONSTRAINT, btree (ws_id, name)
    # Foreign-key constraints:
    #     "upstreams_client_certificate_id_fkey" FOREIGN KEY (client_certificate_id) REFERENCES certificates(id)
    #     "upstreams_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Referenced by:
    #     TABLE "targets" CONSTRAINT "targets_upstream_id_fkey" FOREIGN KEY (upstream_id, ws_id) REFERENCES upstreams(id, ws_id) ON DELETE CASCADE
    # Triggers:
    #     upstreams_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON upstreams FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField(blank=True, null=True)
    hash_on = models.TextField(blank=True, null=True)
    hash_fallback = models.TextField(blank=True, null=True)
    hash_on_header = models.TextField(blank=True, null=True)
    hash_fallback_header = models.TextField(blank=True, null=True)
    hash_on_cookie = models.TextField(blank=True, null=True)
    hash_on_cookie_path = models.TextField(blank=True, null=True)
    slots = models.IntegerField(blank=True, null=True)
    healthchecks = models.JSONField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    algorithm = models.TextField(blank=True, null=True)
    host_header = models.TextField(blank=True, null=True)
    client_certificate_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        app_label = "demo2_kong"
        db_table = "upstreams"

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def get_target(self):
        return KongDataTarget.objects.get(upstream_id=self.id)


class KongDataCertificate(models.Model):
    # ------------+--------------------------+-----------+----------+-------------------------------------------------
    #  id         | uuid                     |           | not null |
    #  created_at | timestamp with time zone |           |          | (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
    #  cert       | text                     |           |          |
    #  key        | text                     |           |          |
    #  tags       | text[]                   |           |          |
    #  ws_id      | uuid                     |           |          |
    #  cert_alt   | text                     |           |          |
    #  key_alt    | text                     |           |          |
    # Indexes:
    #     "certificates_pkey" PRIMARY KEY, btree (id)
    #     "certificates_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "certificates_tags_idx" gin (tags)
    # Foreign-key constraints:
    #     "certificates_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Referenced by:
    #     TABLE "services" CONSTRAINT "services_client_certificate_id_fkey" FOREIGN KEY (client_certificate_id, ws_id) REFERENCES certificates(id, ws_id)
    #     TABLE "snis" CONSTRAINT "snis_certificate_id_fkey" FOREIGN KEY (certificate_id, ws_id) REFERENCES certificates(id, ws_id)
    #     TABLE "upstreams" CONSTRAINT "upstreams_client_certificate_id_fkey" FOREIGN KEY (client_certificate_id) REFERENCES certificates(id)
    # Triggers:
    #     certificates_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON certificates FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cert = models.TextField(blank=True, null=True)
    key = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cert_alt = models.TextField(blank=True, null=True)
    key_alt = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        app_label = "demo2_kong"
        db_table = "certificates"

    def __str__(self):
        return str(self.id)

    @property
    def snis(self):
        queryset = KongDataSNIS.objects.filter(certificate_id=self.id)
        return [item.name for item in queryset]


class KongDataSNIS(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField(blank=True, null=True)
    certificate_id = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        app_label = "demo2_kong"
        db_table = "snis"

    def __str__(self):
        return str(self.id)


class KongDataTarget(models.Model):
    # -------------+--------------------------+-----------+----------+-------------------------------------------------
    #  id          | uuid                     |           | not null |
    #  created_at  | timestamp with time zone |           |          | (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'::text)
    #  upstream_id | uuid                     |           |          |
    #  target      | text                     |           | not null |
    #  weight      | integer                  |           | not null |
    #  tags        | text[]                   |           |          |
    #  ws_id       | uuid                     |           |          |
    # Indexes:
    #     "targets_pkey" PRIMARY KEY, btree (id)
    #     "targets_id_ws_id_unique" UNIQUE CONSTRAINT, btree (id, ws_id)
    #     "targets_tags_idx" gin (tags)
    #     "targets_target_idx" btree (target)
    #     "targets_upstream_id_idx" btree (upstream_id)
    # Foreign-key constraints:
    #     "targets_upstream_id_fkey" FOREIGN KEY (upstream_id, ws_id) REFERENCES upstreams(id, ws_id) ON DELETE CASCADE
    #     "targets_ws_id_fkey" FOREIGN KEY (ws_id) REFERENCES workspaces(id)
    # Triggers:
    #     targets_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON targets FOR EACH ROW EXECUTE FUNCTION sync_tags()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True)
    upstream_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.TextField(blank=True, null=True)
    weight = models.IntegerField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)
    ws_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        app_label = "demo2_kong"
        db_table = "targets"

    def __str__(self):
        return str(self.id)
