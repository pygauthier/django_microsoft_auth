import os

from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='microsoft_auth',
    version='0.1.9',
    packages=find_packages(),
    include_package_data=True,
    description='Simple app to enable Microsoft Account and Office 365 authentication with refresh token',
    long_description=README,
    url='https://bitbucket.org/doyondespres/django_microsoft_auth/',
    author='Pierre-Yves Gauthier',
    author_email='pierre-yves.gauthier@doyondespres.com',
    install_requires=[
        'django>=2.0,<2.3',
        'pyjwt==1.7.1',
        'requests-oauthlib==1.2.0',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
