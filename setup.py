 #!/usr/bin/env python

import io
from os.path import exists

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__version__ = "0.0.5"

setup(
    name='django-common-user-tenants',
    version=__version__,
    author='OmenApps',
    author_email='support@omenapps.com',
    packages=[
        'django_common_user_tenants',
        'django_common_user_tenants.files',
        'django_common_user_tenants.postgresql_backend',
        'django_common_user_tenants.management',
        'django_common_user_tenants.management.commands',
        'django_common_user_tenants.migration_executors',
        'django_common_user_tenants.template',
        'django_common_user_tenants.template.loaders',
        'django_common_user_tenants.templatetags',
        'django_common_user_tenants.test',
        'django_common_user_tenants.tests',
        'django_common_user_tenants.staticfiles',
        'django_common_user_tenants.middleware',
        'django_common_user_tenants.permissions',
        'django_common_user_tenants.permissions.migrations',
    ],
    include_package_data=True,
    scripts=[],
    url='https://github.com/OmenApps/django-common-user-tenants',
    license='MIT License',
    description='Tenant support for Django using PostgreSQL schemas, with common users and multiple tenant types.',
    long_description=io.open('README.rst', encoding='utf-8').read() if exists("README.rst") else "",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    install_requires=[
        'Django >= 2.0,<3.0',
        'psycopg2',
    ],
    zip_safe=False,
)
