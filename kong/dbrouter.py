class KongDBRouter(object):
    route_app_labels = {"demo2_kong"}

    def db_for_read(self, model, **hints):
        """
        Attempts to read demo2_kong models go to "kong_database".
        """
        if model._meta.app_label in self.route_app_labels:
            return "kong_database"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the kong app is involved.
        """
        if (
            obj1._meta.app_label in self.route_app_labels
            or obj2._meta.app_label in self.route_app_labels
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the kong app only appear in the '"kong_database"' database.
        """
        return None
