import os
from contextlib import ContextDecorator

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connections, DEFAULT_DB_ALIAS, connection
from django.contrib.auth import get_user_model
from .models import ExistsError

try:
    from django.apps import apps
    get_model = apps.get_model
except ImportError:
    from django.db.models.loading import get_model

from django.core import mail


def get_tenant_model():
    return get_model(settings.DCUT_TENANT_MODEL)


def get_domain_model():
    return get_model(settings.DCUT_DOMAIN_MODEL)


def get_organization_model():
    return get_model(settings.DCUT_ORGANIZATION_MODEL)


def get_person_model():
    return get_model(settings.DCUT_PERSON_MODEL)


def get_tenant_database_alias():
    return getattr(settings, 'TENANT_DB_ALIAS', DEFAULT_DB_ALIAS)


def get_public_schema_name():
    return getattr(settings, 'PUBLIC_SCHEMA_NAME', 'public')


def get_limit_set_calls():
    return getattr(settings, 'TENANT_LIMIT_SET_CALLS', False)


def get_current_tenant():
    current_schema = connection.get_schema()
    TenantModel = get_tenant_model()
    tenant = TenantModel.objects.get(schema_name=current_schema)
    return tenant


def create_public_tenant(domain_url, owner_email, **owner_extra):
    UserModel = get_user_model()
    TenantModel = get_tenant_model()
    public_schema_name = get_public_schema_name()

    if TenantModel.objects.filter(schema_name=public_schema_name).first():
        raise ExistsError("Public tenant already exists")

    # Create public tenant user. This user doesn't go through object manager
    # create_user function because public tenant does not exist yet
    profile = UserModel.objects.create(
        email=owner_email, is_active=True, **owner_extra
    )
    profile.set_unusable_password()
    profile.save()

    # Create public tenant


    public_tenant = TenantModel.objects.create(schema_name=public_schema_name,
                                               name='Public Tenant',
                                               tenant_type='public',
                                               owner=profile)

    # Add one or more domains for the tenant
    domain = get_domain_model().objects.create(domain=domain_url,
                                                      tenant=public_tenant,
                                                      is_primary=True)

    # Add system user to public tenant (no permissions)
    public_tenant.add_user(profile)


def fix_tenant_urls(domain_url):
    """
    Helper function to update the domain urls on all tenants
    Useful for domain changes in development
    """
    TenantModel = get_tenant_model()
    public_schema_name = get_public_schema_name()

    tenants = TenantModel.objects.all()
    for tenant in tenants:
        if tenant.schema_name == public_schema_name:
            tenant.domain_url = domain_url
        else:
            # Assume the URL is wrong, parse out the subdomain
            # and glue it back to the domain URL configured
            slug = tenant.domain_url.split('.')[0]
            new_url = "{}.{}".format(slug, domain_url)
            tenant.domain_url = new_url
        tenant.save()


def get_creation_fakes_migrations():
    """
    If TENANT_CREATION_FAKES_MIGRATIONS, tenants will be created by cloning an
    existing schema specified by TENANT_CLONE_BASE.
    """
    faked = getattr(settings, 'TENANT_CREATION_FAKES_MIGRATIONS', False)
    if faked:
        if not getattr(settings, 'TENANT_BASE_SCHEMA', False):
            raise ImproperlyConfigured(
                'You must specify a schema name in TENANT_BASE_SCHEMA if '
                'TENANT_CREATION_FAKES_MIGRATIONS is enabled.'
            )
    return faked


def get_tenant_base_schema():
    """
    If TENANT_CREATION_FAKES_MIGRATIONS, tenants will be created by cloning an
    existing schema specified by TENANT_CLONE_BASE.
    """
    schema = getattr(settings, 'TENANT_BASE_SCHEMA', False)
    if schema:
        if not getattr(settings, 'TENANT_CREATION_FAKES_MIGRATIONS', False):
            raise ImproperlyConfigured(
                'TENANT_CREATION_FAKES_MIGRATIONS setting must be True to use '
                'TENANT_BASE_SCHEMA for cloning.'
            )
    return schema


class schema_context(ContextDecorator):
    def __init__(self, *args, **kwargs):
        self.schema_name = args[0]
        super().__init__()

    def __enter__(self):
        self.connection = connections[get_tenant_database_alias()]
        self.previous_tenant = connection.tenant
        self.connection.set_schema(self.schema_name)

    def __exit__(self, *exc):
        if self.previous_tenant is None:
            self.connection.set_schema_to_public()
        else:
            self.connection.set_tenant(self.previous_tenant)


class tenant_context(ContextDecorator):
    def __init__(self, *args, **kwargs):
        self.tenant = args[0]
        super().__init__()

    def __enter__(self):
        self.connection = connections[get_tenant_database_alias()]
        self.previous_tenant = connection.tenant
        self.connection.set_tenant(self.tenant)

    def __exit__(self, *exc):
        if self.previous_tenant is None:
            self.connection.set_schema_to_public()
        else:
            self.connection.set_tenant(self.previous_tenant)


def clean_tenant_url(url_string):
    """
    Removes the TENANT_TOKEN from a particular string
    """
    if hasattr(settings, 'PUBLIC_SCHEMA_URLCONF'):
        if (settings.PUBLIC_SCHEMA_URLCONF and
                url_string.startswith(settings.PUBLIC_SCHEMA_URLCONF)):
            url_string = url_string[len(settings.PUBLIC_SCHEMA_URLCONF):]
    return url_string


def remove_www_and_dev(hostname):
    """
    Legacy function - just in case someone is still using the old name
    """
    return remove_www(hostname)


def remove_www(hostname):
    """
    Removes www. from the beginning of the address. Only for
    routing purposes. www.test.com/login/ and test.com/login/ should
    find the same tenant.
    """
    if hostname.startswith("www."):
        return hostname[4:]

    return hostname


def django_is_in_test_mode():
    """
    I know this is very ugly! I'm looking for more elegant solutions.
    See: http://stackoverflow.com/questions/6957016/detect-django-testing-mode
    """
    return hasattr(mail, 'outbox')


def schema_exists(schema_name):
    _connection = connections[get_tenant_database_alias()]
    cursor = _connection.cursor()

    # check if this schema already exists in the db
    sql = 'SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE LOWER(nspname) = LOWER(%s))'
    cursor.execute(sql, (schema_name, ))

    row = cursor.fetchone()
    if row:
        exists = row[0]
    else:
        exists = False

    cursor.close()

    return exists


def app_labels(apps_list):
    """
    Returns a list of app labels of the given apps_list
    """
    return [app.split('.')[-1] for app in apps_list]


def parse_tenant_config_path(config_path):
    """
    Convenience function for parsing django-tenants' path configuration strings.

    If the string contains '%s', then the current tenant's schema name will be inserted at that location. Otherwise
    the schema name will be appended to the end of the string.

    :param config_path: A configuration path string that optionally contains '%s' to indicate where the tenant
    schema name should be inserted.

    :return: The formatted string containing the schema name
    """
    try:
        # Insert schema name
        return config_path % connection.schema_name
    except (TypeError, ValueError):
        # No %s in string; append schema name at the end
        return os.path.join(config_path, connection.schema_name)
