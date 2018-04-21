---------------
TLS Termination
---------------

Use case
========

.. index:: TLS termination
.. index:: single: TLS;TLS termination
.. index:: single: protcol;HTTP
.. index:: single: protcol;HTTPS

We intend to use the firewall as a `TLS termination proxy <https://en.wikipedia.org/wiki/TLS_termination_proxy>`_ and want to achieve the A+ rate in Qualys SSL Labs `server tester <https://www.ssllabs.com/ssltest/>`_.

Preconditions
=============

Before we modify the firewall configuration the certificate and private key (used to authenticate the server in the HTTPS connection,)should be placed on the firewall host and should be readable by *Zorp*. You can do that by issuing the following (or similar) commands on the firewall host:

.. literalinclude:: scripts/usecase_tls_termination.sh
  :language: shell
  :linenos:

Solution
========

In this case, the clients connect to *Zorp* that acts as a HTTP/HTTPS server, and allows traffic flow according to the rules and communicates with both the clients and the server.  The solution has two part:

#. The incoming HTTPS connection on port ``443`` is terminated and handled by the proxy. After the decryption unencrypted request is passed on the HTTP server.
#. The incoming HTTP connection on port ``80`` is terminated and the client is redirected to the HTTPS location.

.. literalinclude:: sources/https_proxy_tls_termination.py
  :language: python
  :emphasize-lines: 24,31,43,56,66,74,92,98,105,109
  :linenos:

*24.* Server certificate and private key file.

*31.* TLS cipher cuites used by the server in the format of ``openssl ciphers`` command.

*43.* Generic TLS options like version, compression useage, renegotiation support, etc.

*56.* The ``EncryptionPolicy`` which encapsulates all the TLS layer related options.

*66.* Customized ``HttpProxy`` to add ``Strict-Transport-Security`` to each HTTPS response.

*74.* Customized ``HttpProxy`` to redirect each request on HTTP to the same URL on HTTPS.

*92.* *Service.* that runs on incomming connections on port ``443`` and performs the TLS termination.

*98.* *Rule.* that matches on incomming connection that targets the *Zorp.* host on port 443.

*105.* *Service.* that runs on incomming connections on port ``80`` and performs the HTTP to HTTPS redirection.

*109.* *Rule.* that matches on incomming connection that targets the *Zorp.* host on port 80.

Result
======

Now the incoming HTTPS connection goes to the service IP address (``1.2.3.4``) and port ``443`` terminated and the plan *HTTP* traffic is forwared to the server IP address (``10.0.0.1``) on port ``80``.
