from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test
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
        return False


def tenant_permissions_required(login_url=None, raise_exception=False):
    """
    Decorator for views that checks that the user has permissions on the current tenant, redirecting
    to the log-in page if necessary.
    """
    def check_tenant_perms(user):
        # First check if the user is authenticated
        if user.is_authenticated():
            with tenant_context(get_current_tenant()):
                if request.user.has_tenant_permissions():
                    raise True
        # In case the 403 handler should be called raise the exception
        if raise_exception:
            raise PermissionDenied
        # As the last resort, show the login form
        return False
    return user_passes_test(check_tenant_perms, login_url=login_url)

