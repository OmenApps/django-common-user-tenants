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


def tenant_permissions_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user has permissions on the current tenant, redirecting
    to the log-in page if necessary.
    """

    def has_tenant_perms(user):
        with tenant_context(get_current_tenant()):
            return user.has_tenant_permissions()

    actual_decorator = user_passes_test(
        lambda u: has_tenant_perms(u),
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if function:
        return actual_decorator(function)
    return actual_decorator

