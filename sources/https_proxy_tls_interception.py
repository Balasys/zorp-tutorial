# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8

from  Zorp.Core import  *
from  Zorp.Proxy import  *
from  Zorp.Http import  *

from zones import *

EncryptionPolicy(
    name="EncryptionPolicyTlsInterception",
    encryption=TwoSidedEncryption(
        client_verify=ClientNoneVerifier(),
        client_ssl_options=ClientSSLOptions(),
        server_verify=ServerCertificateVerifier(
            ca_directory="/etc/zorp/trusted_store/certs",
            crl_directory="/etc/zorp/trusted_store/crls",
            trusted_certs_directory="",
            trusted=TRUE,
            verify_depth=4,
            permit_invalid_certificates=FALSE,
            permit_missing_crl=FALSE,
            check_subject=TRUE
        ),
        server_ssl_options=ServerSSLOptions(),
        client_certificate_generator=DynamicCertificate(
            private_key=PrivateKey.fromFile(
                key_file_path="/etc/zorp/keys/dynamic_certificate.key"
            ),
            trusted_ca=Certificate.fromFile(
                certificate_file_path="/etc/zorp/certs/trusted_ca.crt",
                private_key=PrivateKey.fromFile("/etc/zorp/keys/trusted_ca.key")
            ),
            untrusted_ca=Certificate.fromFile(
                certificate_file_path="/etc/ca.d/certs/untrusted_ca.crt",
                private_key=PrivateKey.fromFile( "/etc/zorp/keys/untrusted_ca.key"
                )
            )
        )
    )
)

def default() :
    Service(
        name='Service',
        proxy_class=HttpProxy,
        encryption_policy="EncryptionPolicyTlsInterception"
    )

    Rule(
        proto=6,
        src_zone=('client', ),
        dst_zone=('server', ),
        dst_port=(443, ),
        service='ServiceHttpsInterception'
    )
