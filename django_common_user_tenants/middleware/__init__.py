import warnings

from django_common_user_tenants.middleware.main import TenantMainMiddleware


class TenantMiddleware(TenantMainMiddleware):
    def __init__(self, get_response=None):
        super().__init__(get_response=get_response)

        warnings.warn("This class has been renamed to TenantMainMiddleware",
                      DeprecationWarning)
