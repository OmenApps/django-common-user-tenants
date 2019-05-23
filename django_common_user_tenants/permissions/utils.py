from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.decorators import user_passes_test
from ..tenants.utils import get_current_tenant

class TenantPermissionsRequiredMixin(AccessMixin):
    """
    Verify that the current user is has permissions on the current tenant.
    """
    def dispatch(self, request, *args, **kwargs):
        with tenant_context(get_current_tenant()):
            if not request.user.has_tenant_permissions():
                return self.handle_no_permission()
            return super().dispatch(request, *args, **kwargs)



def tenant_permissions_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user has permissions on the current tenant, redirecting
    to the log-in page if necessary.
    """
    with tenant_context(get_current_tenant()):
        actual_decorator = user_passes_test(
            lambda u: u.has_tenant_permissions(),
            login_url=login_url,
            redirect_field_name=redirect_field_name
        )
        if function:
            return actual_decorator(function)
        return actual_decorator

