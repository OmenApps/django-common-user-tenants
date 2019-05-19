import uuid

from django.contrib.sites.shortcuts import get_current_site
import time
from django.db import models, connections, connection, transaction
from django.urls import reverse
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
    Permission, Group
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.conf import settings
from django.dispatch import Signal
from django.core.management import call_command
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .test.cases import TenantTestCase
from .postgresql_backend.base import _check_schema_name
from .permissions.models import UserTenantPermissions, \
    PermissionsMixinFacade
from .clone import CloneSchema
from .signals import post_schema_sync, schema_needs_to_be_sync
from .utils import get_tenant_model, get_creation_fakes_migrations, get_tenant_base_schema
from .utils import schema_exists, get_domain_model, get_public_schema_name, get_tenant_database_alias


# An existing user removed from a tenant
tenant_user_removed = Signal(providing_args=["user", "tenant"])

# An existing user added to a tenant
tenant_user_added = Signal(providing_args=["user", "tenant"])

# A new user is created
tenant_user_created = Signal(providing_args=["user"])

# An existing user is deleted
tenant_user_deleted = Signal(providing_args=["user"])

class InactiveError(Exception):
    pass

class ExistsError(Exception):
    pass

class DeleteError(Exception):
    pass

class SchemaError(Exception):
    pass

def schema_required(func):
    def inner(self, *args, **options):
        tenant_schema = self.schema_name
        # Save current schema and restore it when we're done
        saved_schema = connection.get_schema()
        # Set schema to this tenants schema to start building permissions in that tenant
        connection.set_schema(tenant_schema)
        try:
            result = func(self, *args, **options)
        finally:
            # Even if an exception is raised we need to reset our schema state
            connection.set_schema(saved_schema)
        return result
    return inner


class TenantBase(models.Model):
    """
    Contains global data and settings for the tenant model.
    """
    slug = models.SlugField(_('Tenant URL Name'), blank=True)

    # The owner of the tenant. Only they can delete it. This can be changed, but it
    # can't be blank. There should always be an owner.
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    # Pull the tenant name choices from TENANT_LISTING dictionary keys
    TENANT_TYPE = tuple([('public', 'public')] + [(tpl, tpl) for tpl in tuple(settings.TENANT_LISTING.keys())])
    tenant_type = models.CharField(max_length=20, choices=TENANT_TYPE, default=TENANT_TYPE[0])

    # Schema will be automatically created and synced when it is saved
    auto_create_schema = True
    # Schema will be automatically deleted when related tenant is deleted
    auto_drop_schema = True

    schema_name = models.CharField(max_length=63, unique=True, db_index=True,
                                   validators=[_check_schema_name])

    domain_url = None
    """
    Leave this as None. Stores the current domain url so it can be used in the logs
    """

    _previous_tenant = []

    def __enter__(self):
        """
        Syntax sugar which helps in celery tasks, cron jobs, and other scripts

        Usage:
            with Tenant.objects.get(schema_name='test') as tenant:
                # run some code in tenant test
            # run some code in previous tenant (public probably)
        """
        connection = connections[get_tenant_database_alias()]
        self._previous_tenant.append(connection.tenant)
        self.activate()

    def __exit__(self, exc_type, exc_val, exc_tb):
        connection = connections[get_tenant_database_alias()]

        connection.set_tenant(self._previous_tenant.pop())


    def activate(self):
        """
        Syntax sugar that helps at django shell with fast tenant changing

        Usage:
            Tenant.objects.get(schema_name='test').activate()
        """
        connection = connections[get_tenant_database_alias()]
        connection.set_tenant(self)

    @classmethod
    def deactivate(cls):
        """
        Syntax sugar, return to public schema

        Usage:
            test_tenant.deactivate()
            # or simpler
            Tenant.deactivate()
        """
        connection = connections[get_tenant_database_alias()]
        connection.set_schema_to_public()


    def save(self, verbosity=1, *args, **kwargs):
        if not self.pk:
            self.created = timezone.now()
        self.modified = timezone.now()

        connection = connections[get_tenant_database_alias()]
        is_new = self.pk is None
        has_schema = hasattr(connection, 'schema_name')
        if has_schema and is_new and connection.schema_name != get_public_schema_name():
            raise Exception("Can't create tenant outside the public schema. "
                            "Current schema is %s." % connection.schema_name)
        elif has_schema and not is_new and connection.schema_name not in (self.schema_name, get_public_schema_name()):
            raise Exception("Can't update tenant outside it's own schema or "
                            "the public schema. Current schema is %s."
                            % connection.schema_name)

        super(TenantBase, self).save(*args, **kwargs)

        if has_schema and is_new and self.auto_create_schema:
            try:
                self.create_schema(check_if_exists=True, verbosity=verbosity)
                post_schema_sync.send(sender=TenantBase, tenant=self.serializable_fields())
            except Exception:
                # We failed creating the tenant, delete what we created and
                # re-raise the exception
                self.delete(force_drop=True)
                raise
        elif is_new:
            # although we are not using the schema functions directly, the signal might be registered by a listener
            schema_needs_to_be_sync.send(sender=TenantBase, tenant=self.serializable_fields())
        elif not is_new and self.auto_create_schema and not schema_exists(self.schema_name):
            # Create schemas for existing models, deleting only the schema on failure
            try:
                self.create_schema(check_if_exists=True, verbosity=verbosity)
                post_schema_sync.send(sender=TenantBase, tenant=self.serializable_fields())
            except Exception:
                # We failed creating the schema, delete what we created and
                # re-raise the exception
                self._drop_schema()
                raise

    def serializable_fields(self):
        """ in certain cases the user model isn't serializable so you may want to only send the id """
        return self

    def _drop_schema(self, force_drop=False):
        """ Drops the schema"""
        connection = connections[get_tenant_database_alias()]
        has_schema = hasattr(connection, 'schema_name')
        if has_schema and connection.schema_name not in (self.schema_name, get_public_schema_name()):
            raise Exception("Can't delete tenant outside it's own schema or "
                            "the public schema. Current schema is %s."
                            % connection.schema_name)

        if has_schema and schema_exists(self.schema_name) and (self.auto_drop_schema or force_drop):
            self.pre_drop()
            cursor = connection.cursor()
            cursor.execute('DROP SCHEMA %s CASCADE' % self.schema_name)

    def pre_drop(self):
        """
        This is a routine which you could override to backup the tenant schema before dropping.
        :return:
        """

    def delete(self, force_drop=False, *args, **kwargs):
        if force_drop:
            self._drop_schema(force_drop)
        else:
            raise DeleteError("Not supported -- delete_tenant() should be used.")

        super().delete(*args, **kwargs)

    def create_schema(self, check_if_exists=False, sync_schema=True,
                      verbosity=1):
        """
        Creates the schema 'schema_name' for this tenant. Optionally checks if
        the schema already exists before creating it. Returns true if the
        schema was created, false otherwise.
        """

        # safety check
        connection = connections[get_tenant_database_alias()]
        _check_schema_name(self.schema_name)
        cursor = connection.cursor()

        if check_if_exists and schema_exists(self.schema_name):
            return False

        fake_migrations = get_creation_fakes_migrations()

        if sync_schema:
            if fake_migrations:
                # copy tables and data from provided model schema
                base_schema = get_tenant_base_schema()
                clone_schema = CloneSchema()
                clone_schema.clone_schema(base_schema, self.schema_name)

                call_command('migrate_schemas',
                             tenant=True,
                             fake=True,
                             schema_name=self.schema_name,
                             interactive=False,
                             verbosity=verbosity)
            else:
                # create the schema
                cursor.execute('CREATE SCHEMA %s' % self.schema_name)
                call_command('migrate_schemas',
                             tenant=True,
                             schema_name=self.schema_name,
                             interactive=False,
                             verbosity=verbosity)

        connection.set_schema_to_public()

    def get_primary_domain(self):
        """
        Returns the primary domain of the tenant
        """
        try:
            domain = self.domains.get(is_primary=True)
            return domain
        except get_domain_model().DoesNotExist:
            return None

    def reverse(self, request, view_name):
        """
        Returns the URL of this tenant.
        """
        http_type = 'https://' if request.is_secure() else 'http://'

        domain = get_current_site(request).domain

        url = ''.join((http_type, self.schema_name, '.', domain, reverse(view_name)))

        return url

    @schema_required
    def add_user(self, user_obj, is_superuser=False, is_staff=False):
        # User already is linked here..
        if self.user_set.filter(id=user_obj.id).exists():
            raise ExistsError("User already added to tenant: %s" % user_obj)

        # User not linked to this tenant, so we need to create tenant permissions
        user_tenant_perms = UserTenantPermissions.objects.create(
            profile=user_obj,
            is_staff=is_staff,
            is_superuser=is_superuser
        )
        # Link user to tenant
        user_obj.tenants.add(self)

        tenant_user_added.send(sender=self.__class__, user=user_obj, tenant=self)

    @schema_required
    def remove_user(self, user_obj):
        # Test that user is already in the tenant
        self.user_set.get(id=user_obj.id)

        if not user_obj.is_active:
            raise InactiveError("User specified is not an active user: %s" % user_obj)

        # Dont allow removing an owner from a tenant. This must be done
        # Through delete tenant or transfer_ownership
        if user_obj.id == self.owner.id:
            raise DeleteError("Cannot remove owner from tenant: %s" % self.owner)

        user_tenant_perms = user_obj.usertenantpermissions

        # Remove all current groups from user..
        groups = user_tenant_perms.groups
        groups.clear()

        # Unlink from tenant
        UserTenantPermissions.objects.filter(id=user_tenant_perms.id).delete()
        user_obj.tenants.remove(self)

        tenant_user_removed.send(sender=self.__class__, user=user_obj, tenant=self)

    def delete_tenant(self):
        '''
        We don't actually delete the tenant out of the database, but we associate them
        with a the public schema user and change their url to reflect their delete
        datetime and previous owner
        The caller should verify that the user deleting the tenant owns the tenant.
        '''
        # Prevent public tenant schema from being deleted
        if self.schema_name == get_public_schema_name():
            raise ValueError("Cannot delete public tenant schema")

        for user_obj in self.user_set.all():
            # Don't delete owner at this point
            if user_obj.id == self.owner.id:
                continue
            self.remove_user(user_obj)

        # Seconds since epoch, time() returns a float, so we convert to
        # an int first to truncate the decimal portion
        time_string = str(int(time.time()))
        new_url = "{}-{}-{}".format(
            time_string,
            str(self.owner.id),
            self.domain_url
        )
        self.domain_url = new_url
        # The schema generated each time (even with same url slug) will be unique.
        # So we do not have to worry about a conflict with that

        # Set the owner to the system user (public schema owner)
        public_tenant = get_tenant_model().objects.get(schema_name=get_public_schema_name())

        old_owner = self.owner

        # Transfer ownership to system
        self.transfer_ownership(public_tenant.owner)

        # Remove old owner as a user if the owner still exists after the transfer
        if self.user_set.filter(id=user_obj.id).exists():
            self.remove_user(old_owner)

    @schema_required
    def transfer_ownership(self, new_owner):
        old_owner = self.owner

        # Remove current owner superuser status but retain any assigned role(s)
        old_owner_tenant = old_owner.usertenantpermissions
        old_owner_tenant.is_superuser = False
        old_owner_tenant.save()

        self.owner = new_owner

        # If original has no permissions left, remove user from tenant
        if not old_owner_tenant.groups.exists():
            self.remove_user(old_owner)

        try:
            # Set new user as superuser in this tenant if user already exists
            user = self.user_set.get(id=new_owner.id)
            user_tenant = user.usertenantpermissions
            user_tenant.is_superuser = True
            user_tenant.save()
        except get_user_model().DoesNotExist:
            # New user is not a part of the system, add them as a user..
            self.add_user(new_owner, is_superuser=True)

        self.save()

    class Meta:
        abstract = True


class UserProfileManager(BaseUserManager):
    def _create_user(self, email, password, is_staff, is_superuser, is_verified, **extra_fields):
        # Do some schema validation to protect against calling create user from inside
        # a tenant. Must create public tenant permissions during user creation. This
        # happens during assign role. This function cannot be used until a public
        # schema already exists
        UserModel = get_user_model()

        if connection.get_schema() != get_public_schema_name():
            raise SchemaError("Schema must be public for UserProfileManager user creation")

        if not email:
            raise ValueError("Users must have an email address.")

        # If no password is submitted, just assign a random one to lock down
        # the account a little bit.
        if not password:
            password = self.make_random_password(length=30)

        email = self.normalize_email(email)

        profile = UserModel.objects.filter(email=email).first()
        if profile and profile.is_active:
            raise ExistsError("User already exists!")

        # Profile might exist but not be active. If a profile does exist
        # all previous history logs will still be associated with the user,
        # but will not be accessible because the user won't be linked to
        # any tenants from the user's previous membership. There are two
        # exceptions to this. 1) The user gets re-invited to a tenant it
        # previously had access to (this is good thing IMO). 2) The public
        # schema if they had previous activity associated would be available
        if not profile:
            profile = UserModel()

        profile.email = email
        profile.is_active = True
        profile.is_verified = is_verified
        profile.set_password(password)
        for attr, value in extra_fields.items():
            setattr(profile, attr, value)
        profile.save()

        # Get public tenant tenant and link the user (no perms)
        public_tenant = get_tenant_model().objects.get(schema_name=get_public_schema_name())
        public_tenant.add_user(profile)

        # Public tenant permissions object was created when we assigned a
        # role to the user above, if we are a staff/superuser we set it here
        if is_staff or is_superuser:
            user_tenant = profile.usertenantpermissions
            user_tenant.is_staff = is_staff
            user_tenant.is_superuser = is_superuser
            user_tenant.save()

        tenant_user_created.send(sender=self.__class__, user=profile)

        return profile

    def create_user(self, email=None, password=None, is_staff=False, **extra_fields):
        return self._create_user(email, password, is_staff, False, False, **extra_fields)

    def create_superuser(self, password, email=None, **extra_fields):
        return self._create_user(email, password, True, True, True, **extra_fields)

    def delete_user(self, user_obj):
        if not user_obj.is_active:
            raise InactiveError("User specified is not an active user!")

        # Check to make sure we don't try to delete the public tenant owner
        # that would be bad....
        public_tenant = get_tenant_model().objects.get(schema_name=get_public_schema_name())
        if user_obj.id == public_tenant.owner.id:
            raise DeleteError("Cannot delete the public tenant owner!")

        # This includes the linked public tenant 'tenant'. It will delete the
        # Tenant permissions and unlink when user is deleted
        for tenant in user_obj.tenants.all():
            # If user owns the tenant, we call delete on the tenant
            # which will delete the user from the tenant as well
            if tenant.owner.id == user_obj.id:
                # Delete tenant will handle any other linked users to that tenant
                tenant.delete_tenant()
            else:
                # Unlink user from all roles in any tenant it doesn't own
                tenant.remove_user(user_obj)

        # Set is_active, don't actually delete the object
        user_obj.is_active = False
        user_obj.save()

        tenant_user_deleted.send(sender=self.__class__, user=user_obj)

    def get_tenants(self, user_obj, tenant_type=None):
        '''
        If provided a tenant_type, returns all the user's associated tenants of that type.
        Otherwise returns all user's associated tenants EXCEPT Public Tenant
        '''
        if tenant_type is not None:
            return user_obj.tenants.filter(tenant_type=tenant_type)
        else:
            return user_obj.tenants.exclude(tenant_type='public')


# This cant be located in the users app otherwise it would get loaded into
# both the public schema and all tenant schemas. We want profiles only
# in the public schema alongside the TenantBase model
class UserProfile(AbstractBaseUser, PermissionsMixinFacade):
    """
    An authentication-only model that is in the public tenant schema but
    linked from the authorization model (UserTenantPermissions)
    where as to allow for one global profile (public schema) for each user
    but maintain permissions on a per tenant basis.
    To access permissions for a user, the request must come through the
    tenant that permissions are desired for.
    Requires use of the ModelBackend
    """

    USERNAME_FIELD = "email"
    objects = UserProfileManager()

    tenants = models.ManyToManyField(
        settings.DCUT_TENANT_MODEL,
        verbose_name=_('tenants'),
        blank=True,
        help_text=_('The tenants this user belongs to.'),
        related_name="user_set"
    )

    email = models.EmailField(
        _("Email Address"),
        unique = True,
        db_index = True,
    )

    is_active = models.BooleanField(_('active'), default=True)

    # Tracks whether the user's email has been verified
    is_verified = models.BooleanField(_('verified'), default=False)

    class Meta:
        abstract = True

    def has_verified_email(self):
        return self.is_verified == True

    def delete(self, force_drop=False, *args, **kwargs):
        if force_drop:
            super().delete(*args, **kwargs)
        else:
            raise DeleteError("UserProfile.objects.delete_user() should be used.")

    def __unicode__(self):
        return self.email

    def get_short_name(self):
        return self.email

    def get_full_name(self):
        return str(self)  # just use __unicode__ here.


class DomainMixin(models.Model):
    """
    All models that store the domains must inherit this class
    """
    domain = models.CharField(max_length=253, unique=True, db_index=True)
    tenant = models.ForeignKey(settings.DCUT_TENANT_MODEL, db_index=True, related_name='domains',
                               on_delete=models.CASCADE)

    # Set this to true if this is the primary domain
    is_primary = models.BooleanField(default=True, db_index=True)

    @transaction.atomic
    def save(self, *args, **kwargs):
        # Get all other primary domains with the same tenant
        domain_list = self.__class__.objects.filter(tenant=self.tenant, is_primary=True).exclude(pk=self.pk)
        # If we have no primary domain yet, set as primary domain by default
        self.is_primary = self.is_primary or (not domain_list.exists())
        if self.is_primary:
            # Remove primary status of existing domains for tenant
            domain_list.update(is_primary=False)
        super().save(*args, **kwargs)

    class Meta:
        abstract = True


class OrganizationMixin(models.Model):
    name = models.CharField(_("Name"),
                            max_length=100,
                            blank=False,
                            unique=True,
                            help_text="Organization Name"
                            )
    owner = models.ForeignKey(settings.DCUT_PERSON_MODEL,
                              blank=True,
                              on_delete=models.CASCADE,
                              related_name="owners_organizations"
                              )
    tenant = models.OneToOneField(settings.DCUT_TENANT_MODEL,
                                  null=True,
                                  blank=True,
                                  on_delete=models.CASCADE,
                                  related_name="tenants_organization"
                                  )

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class PersonMixin(models.Model):
    """
    Makes it possible to have accounts managed by the district or WaterUser in cases where there is no associated user
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, blank=True, on_delete=models.CASCADE, related_name="users_person")
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        abstract = True
