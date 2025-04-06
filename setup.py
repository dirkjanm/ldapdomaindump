from setuptools import setup
setup(name='ldapdomaindump',
      version='0.10.1',
      description='Active Directory information dumper via LDAP',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/dirkjanm/ldapdomaindump/',
      packages=['ldapdomaindump'],
      requires_python=">=3.6",
      install_requires=['dnspython', 'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6'],
      package_data={'ldapdomaindump': ['style.css']},
      include_package_data=True,
      entry_points= {
        'console_scripts': ['ldapdomaindump=ldapdomaindump:main','ldd2bloodhound=ldapdomaindump.convert:ldd2bloodhound','ldd2pretty=ldapdomaindump.pretty:main']
      },
      license="MIT",
      )
