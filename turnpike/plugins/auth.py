import base64
import importlib
import json
import logging

from flask import request

from ..plugin import TurnpikePlugin, TurnpikeAuthPlugin


logger = logging.getLogger(__name__)


class AuthPlugin(TurnpikePlugin):
    def __init__(self, app):
        super().__init__(app)
        self.auth_plugins = []
        for plugin_name in self.app.config["AUTH_PLUGIN_MAP"]:
            mod_name, cls_name = plugin_name.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name)
            if not issubclass(cls, TurnpikeAuthPlugin):
                raise ValueError(f"Auth plugin {plugin_name} is not a TurnpikeAuthPlugin.")
            plugin_instance = cls(app)
            plugin_instance.register_blueprint()
            self.auth_plugins.append(plugin_instance)
        self.backend_map = {backend["route"]: backend.get("auth", {}) for backend in self.app.config["BACKENDS"]}

    def make_identity_header(self, identity_type, auth_type, auth_data):
        header_data = dict(
            identity=dict(type=identity_type, auth_type=auth_type, **{identity_type.lower(): auth_data})
        )
        logger.debug(header_data)
        return base64.encodebytes(json.dumps(header_data).encode("utf8")).replace(b"\n", b"")

    def process(self, context):
        logger.debug("Begin auth")
        original_url = request.headers.get("X-Original-Uri", "/api/turnpike/identity")

        matches = [backend for backend in self.backend_map if original_url.startswith(backend)]
        if not matches:
            # This condition shouldn't be hit - it would mean that there was a
            # bug, a mismatch between the routes configured in nginx and the
            # routes configured here.
            context.status_code = 403
            return context
        backend_name = max(matches, key=lambda match: len(match))
        logger.debug(f"Matched backend: {backend_name}")
        backend_auth = self.backend_map[backend_name]

        # If the route does not require authentication, then we defer to other
        # plugins.
        if not backend_auth:
            logger.debug("No auth required for backend")
            return context
        for auth_plugin in self.auth_plugins:
            context = auth_plugin.process(backend_auth, context)
            if context.auth or context.status_code:
                # The auth plugin authenticated the user or wants to return immediately
                logger.debug(f"Auth complete: {context}")
                if context.auth:
                    context.headers["X-RH-Identity"] = self.make_identity_header(
                        "Associate", auth_plugin.name, context.auth
                    )
                return context

        # If we get here, no plugin reported successful authentication.
        context.status_code = 401
        context.headers["login_url"] = next(
            url for url in [plugin.login_url() for plugin in self.auth_plugins] if url is not None
        )
        return context