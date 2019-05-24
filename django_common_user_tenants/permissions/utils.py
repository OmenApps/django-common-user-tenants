from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import PermissionDenied
from ..tenants.utils import get_current_tenant, tenant_context


class TenantPermissionsRequiredMixin(AccessMixin):
    """
    Verify that the current user is has permissions on the current tenant.
    """
    def dispatch(self, request, *args, **kwargs):
        with tenant_context(get_current_tenant()):
            if not request.user.has_tenant_permissions():
                raise PermissionDenied
            return super().dispatch(request, *args, **kwargs)


def tenant_permissions_required(function):
    """
    Decorator for views that checks that the user has permissions on the current tenant, redirecting
    to the log-in page if necessary.
    """
    with tenant_context(get_current_tenant()):
        def _inner(request, *args, **kwargs):
            if not request.user.has_tenant_permissions():
                raise PermissionDenied           
            return function(request, *args, **kwargs)
        return _inner


