import pytest
from ldapdomaindump.authentication import ADAuthentication


def test_init_splits_upn_username():
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='target.local', auth_method='auto',
                            ldap_channel_binding=False)
    assert auth.username == 'alice'
    assert auth.userdomain == 'corp.local'
    assert auth.domain == 'target.local'


def test_init_domain_lowercased():
    auth = ADAuthentication(username='alice', password='pw',
                            domain='CORP.LOCAL', auth_method='auto',
                            ldap_channel_binding=False)
    assert auth.domain == 'corp.local'
    assert auth.userdomain == 'corp.local'


def test_init_sets_defaults():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    assert auth.tgt is None
    assert auth.lm_hash == ''
    assert auth.nt_hash == ''
    assert auth.aeskey == ''
    assert auth.use_ccache is False


def test_set_kdc_syncs_userdomain_kdc_when_same_domain():
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='auto',
                            ldap_channel_binding=False)
    auth.set_kdc('dc.corp.local')
    assert auth.kdc == 'dc.corp.local'
    assert auth.userdomain_kdc == 'dc.corp.local'


def test_set_kdc_does_not_sync_when_cross_realm():
    auth = ADAuthentication(username='alice@user.local', password='pw',
                            domain='target.local', auth_method='auto',
                            ldap_channel_binding=False)
    auth.set_kdc('dc.target.local')
    assert auth.kdc == 'dc.target.local'
    assert auth.userdomain_kdc == 'user.local'


def test_set_aeskey():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    auth.set_aeskey('a' * 64)
    assert auth.aeskey == 'a' * 64
