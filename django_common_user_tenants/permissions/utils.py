from functools import wraps
from urllib.parse import urlparse

from django.conf import settings
from django.shortcuts import resolve_url
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import PermissionDenied

from ..tenants.utils import get_current_tenant, get_public_tenant, tenant_context


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


def tenant_user_passes_test(test_func, login_url=None, redirect_field_name=REDIRECT_FIELD_NAME, tenant=None):
    """
    Decorator for views that checks that the user passes the given test,
    redirecting to the public Tenant log-in page if necessary. The test should be a
    callable that takes the user object and returns True if the user passes.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request.user):
                return view_func(request, *args, **kwargs)
            with tenant_context(tenant):
                path = request.build_absolute_uri()
                resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
                # If the login url is the same scheme and net location then just
                # use the path as the "next" url.
                login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
                current_scheme, current_netloc = urlparse(path)[:2]
                if ((not login_scheme or login_scheme == current_scheme) and
                        (not login_netloc or login_netloc == current_netloc)):
                    path = request.get_full_path()
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(
                    path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    return decorator


def tenant_permissions_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user has permissions on the current tenant, redirecting
    to the log-in page if necessary.
    """

    def has_tenant_perms(user):
        if user.is_authenticated:
            with tenant_context(get_current_tenant()):
                return user.has_tenant_permissions()
        return False

    actual_decorator = tenant_user_passes_test(
        lambda u: has_tenant_perms(u),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
        tenant=get_public_tenant(),
    )
    if function:
        return actual_decorator(function)
    return actual_decorator


