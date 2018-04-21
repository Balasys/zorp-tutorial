from Zorp.Core import init

from Zorp.Core import FALSE, TRUE
from Zorp.Router import DirectedRouter
from Zorp.Rule import Rule
from Zorp.Service import Service
from Zorp.SockAddr import SockAddrInet
from Zorp.Http import AbstractHttpProxy, HttpProxy, HTTP_HDR_INSERT, HTTP_REQ_POLICY, HTTP_REQ_REJECT
from Zorp.Encryption import \
    EncryptionPolicy, \
    ClientOnlyEncryption, \
    ClientOnlyStartTLSEncryption, \
    ClientNoneVerifier, \
    ClientSSLOptions, \
    StaticCertificate, \
    Certificate, PrivateKey, \
    SSL_METHOD_ALL, \
    SSL_CIPHERS_CUSTOM

from datetime import timedelta

from Zorp.Core import config

CERTIFICATE = Certificate.fromFile(
    certificate_file_path="/etc/zorp/certs/server.pem",
    private_key=PrivateKey.fromFile(
        key_file_path="/etc/zorp/keys/server.pem",
    )
)

CIPHERS = \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384:" \
    "ECDHE-ECDSA-CHACHA20-POLY1305:" \
    "ECDHE-RSA-CHACHA20-POLY1305:" \
    "ECDHE-ECDSA-AES128-GCM-SHA256:" \
    "ECDHE-RSA-AES128-GCM-SHA256:" \
    "ECDHE-ECDSA-AES256-SHA384:" \
    "ECDHE-RSA-AES256-SHA384:" \
    "ECDHE-ECDSA-AES128-SHA256:" \
    "ECDHE-RSA-AES128-SHA256"

CLIENT_SSL_OPTIONS = ClientSSLOptions(
    method=SSL_METHOD_ALL,
    cipher=(SSL_CIPHERS_CUSTOM, CIPHERS),
    cipher_server_preference=TRUE,
    disable_sslv2=TRUE,
    disable_sslv3=TRUE,
    disable_tlsv1=TRUE,
    disable_tlsv1_1=TRUE,
    disable_tlsv1_2=FALSE,
    disable_compression=TRUE,
    disable_renegotiation=FALSE,
)

EncryptionPolicy(
    name="EncryptionPolicyTlsTermination",
    encryption=ClientOnlyEncryption(
        client_certificate_generator=StaticCertificate(certificate=CERTIFICATE),
        client_ssl_options=CLIENT_SSL_OPTIONS,
        client_verify=ClientNoneVerifier(),
    )
)


class HttpProxySecurityHeaders(HttpProxy):
    def config(self):
        HttpProxy.config(self)

        hsts_header_value = "max-age=%d" % (timedelta(days=365).total_seconds())
        self.response_header["Strict-Transport-Security"] = (HTTP_HDR_INSERT, hsts_header_value)


class HttpProxyHttpsRedirect(AbstractHttpProxy):
    def config(self):
        AbstractHttpProxy.config(self)

        self.error_silent = TRUE
        self.request["*"] = (HTTP_REQ_POLICY, self.redirectRequest)

    def redirectRequest(self, method, url, version):
        self.error_status = 301
        self.error_headers = "Location: https://%s/\n" % (self.request_url_host, )

        return HTTP_REQ_REJECT


def default():
    service_address = '1.2.3.4'
    server_address = '10.0.0.1'

    Service(
        name="ServiceHttpTlsTermination",
        proxy_class=HttpProxySecurityHeaders,
        encryption_policy="EncryptionPolicyTlsTermination",
        router=DirectedRouter(dest_addr=SockAddrInet(server_address, 80), forge_addr=FALSE),
    )
    Rule(
        proto=6,
        dst_subnet=(service_address + '/32', ),
        dst_port=(443, ),
        service='ServiceHttpTlsTermination'
    )

    Service(
        name="ServiceHttpToHttpsRedirection",
        proxy_class=HttpProxyHttpsRedirect,
    )
    Rule(
        proto=6,
        dst_subnet=(service_address + '/32', ),
        dst_port=(80, ),
        service='ServiceHttpToHttpsRedirection'
    )
