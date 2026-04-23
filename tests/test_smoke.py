def test_package_imports():
    import ldapdomaindump
    assert hasattr(ldapdomaindump, 'main')
