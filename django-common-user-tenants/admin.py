class TenantAdminMixin(object):
    """
    Mixin for Tenant model:
    It disables save and delete buttons when not in current or public tenant (preventing Exceptions).
    """
    change_form_template = 'admin/django_common_user_tenants/tenant/change_form.html'
