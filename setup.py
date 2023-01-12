from setuptools import setup
setup(name='ldapdomaindump',
      version='0.9.4',
      description='Active Directory information dumper via LDAP',
      author='Dirk-jan Mollema',
      author_email='dirkjan@sanoweb.nl',
      url='https://github.com/dirkjanm/ldapdomaindump/',
      packages=['ldapdomaindump'],
      install_requires=['dnspython', 'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6', 'future'],
      package_data={'ldapdomaindump': ['style.css']},
      include_package_data=True,
      scripts=['bin/ldapdomaindump', 'bin/ldd2bloodhound', 'bin/ldd2pretty'],
      license="MIT",
      )
