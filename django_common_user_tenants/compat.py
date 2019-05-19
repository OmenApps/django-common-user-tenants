from .test.cases import TenantTestCase
from .tenants.utils import (get_public_schema_name, get_tenant_model,
                                  get_tenant_domain_model, schema_context)
from .tenants.models import TenantBase

TENANT_SCHEMAS = False
