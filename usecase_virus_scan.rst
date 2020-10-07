----------
Virus Scan
----------

Use case
========

.. index:: Virus scan
.. index:: ClamAV

We intend to virus scan on the firewall using external application.

Solution
========

In this case, the clients connect to *Zorp* that acts as a HTTP/HTTPS server, and allows traffic flow according to the rules and communicates with both the clients and the server.  The solution has two part:

#. The incoming HTTPS connection on port ``443`` is terminated and handled by the proxy. After decriptionthe unencrypted request is passed on the HTTP server.
#. The incoming HTTP connection on port ``80`` is terminated and the client is redirected to the HTTPS location.

.. literalinclude:: sources/http_proxy_virus_scan.py
  :language: python
  :emphasize-lines: 24,31,43,56,66,74,92,98,109
  :linenos:

1. Server certificate and private key file.
2. TLS cipher cuites used by the server in the format of ``openssl ciphers`` command.
3. Generic TLS options like version, compression useage, renegotiation support, etc.
4. The ``EncryptionPolicy`` which encapsulates all the TLS layer related options.
5. Customized ``HttpProxy`` to add ``Strict-Transport-Security`` to each HTTPS response.
6. Customized ``HttpProxy`` to redirect each request on HTTP to the same URL on HTTPS.
7. *Service* that runs on incomming connections on port ``443`` and performs the TLS termination.
8. *Rule* that matches on incomming connection that targets the *Zorp* host on port 443.
9. *Service* that runs on incomming connections on port ``80`` and performs the HTTP to HTTPS redirection.
10. *Rule* that matches on incomming connection that targets the *Zorp* host on port 80.

Result
======

Now the incoming HTTPS connection goes to the service IP address (``1.2.3.4``) and port ``443`` terminated and the plan *HTTP* traffic is forwared to the server IP address (``10.0.0.1``) on port ``80``.
