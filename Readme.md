# ArkCase Gateway using Apache Reverse Proxying

This container provides an easy mechanism to deploy an Apache server which can be very flexibly configured using YAML. It's meant to be used as a reverse proxy in front of "whatever", but can really be used to serve up anything else we wish.

This is an example configuration file that can be used:

```yaml
################################################################################
# NOTE: Not all sections/options are required - this is simply an example      #
#       illustrating the options that are available to be used within this     #
#       configuration file                                                     #
################################################################################

main:
  serverAdmin: "webmaster@localhost"
  documentRoot: "/var/www/html"
  timeOut: 300
  keepAlive: "On"
  maxKeepAliveRequests: 100
  keepAliveTimeout: 5
  hostnameLookups: "Off"
  accessFileName: ".htaccess"
  log:
    level: warn
    error: "${APACHE_LOG_DIR}/error.log"
    custom: "${APACHE_LOG_DIR}/access.log combined"
  includes:
    - "/some/path/include-file-1.conf"
    - "/some/path/include-file-2.conf"
    # ...
    - "/some/path/include-file-3.conf"

ssl:
  cert: inc:cert.pem
  key: inc:key.pem
  ca:
    # This "inc:..." syntax allows us to include files as required,
    # such that we have some flexibility regarding the files' location.
    # an absolute path is computed relative to /conf, while a relative
    # path is computed relative to the location of the configuration file
    # being consumed by the configurator tool (by default /conf as well)
    - inc:ca.1

    # File contents may also be provided inline
    - |
      -----BEGIN CERTIFICATE-----
      MIIFQjCCBCqgAwIBAgIBEjANBgkqhkiG9w0BAQsFADCBtzELMAkGA1UEBhMCQ1Ix
      ETAPBgNVBAgTCFNhbiBKb3NlMRIwEAYDVQQHEwlTYW50YSBBbmExFzAVBgNVBAoT
      DkVydWRpY2l0eSBTLkEuMRwwGgYDVQQLExNTZWN1cml0eSBPcGVyYXRpb25zMSMw
      IQYDVQQDExpFcnVkaWNpdHkgMjA0OC1iaXQgUm9vdCBDQTElMCMGCSqGSIb3DQEJ
      ARYWc2VjdXJpdHlAZXJ1ZGljaXR5LmNvbTAeFw0yMDA3MTUyMjMwNDRaFw0zMDA3
      MTMyMjMwNDRaMIGZMQswCQYDVQQGEwJDUjERMA8GA1UECBMIU2FuIEpvc2UxFzAV
      BgNVBAoTDkVydWRpY2l0eSBTLkEuMRwwGgYDVQQLExNTZWN1cml0eSBPcGVyYXRp
      b25zMRkwFwYDVQQDExBkaWVnby5yaXZlcmEucHJ2MSUwIwYJKoZIhvcNAQkBFhZz
      ZWN1cml0eUBlcnVkaWNpdHkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
      CgKCAQEApQRdDGKWjYNLBFTpByW1qlnMz8bdHOfPrRfJFFS4M/jpgBb0wiktiTyj
      7Rks/kuMje0VRlOykQEXOI91TPLZLMC4jraiZ63NEiRTT3QrxrfcqSIH5vCKSdA8
      NkrS9LFaO5iafXERotiQMIYzxBai93c1Qq286v3BPTOHQpBGohXToFF40zfINddO
      Pm8KJuxbJWyCnIDta32XCjG3IDUVklZgqX2iLshr/mckY57wDmZOndvbSaVyg13s
      GadzxQpJ6u2YWZZxZq3ZIV6oqF/PhvPDFS/jq7FQgmfKh67OsIBJuJfHSJhrMh83
      YsToNcscZWXL9z8bqDOj3oOktAIctQIDAQABo4IBczCCAW8wCQYDVR0TBAIwADAs
      BglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYD
      VR0OBBYEFHs4ocuvJ4Yqm5/3DiqsGkcJ40xFMIH3BgNVHSMEge8wgeyAFAvWsA/U
      tLnlxg44/mmBUjcGXoXsoYG9pIG6MIG3MQswCQYDVQQGEwJDUjERMA8GA1UECBMI
      U2FuIEpvc2UxEjAQBgNVBAcTCVNhbnRhIEFuYTEXMBUGA1UEChMORXJ1ZGljaXR5
      IFMuQS4xHDAaBgNVBAsTE1NlY3VyaXR5IE9wZXJhdGlvbnMxIzAhBgNVBAMTGkVy
      dWRpY2l0eSAyMDQ4LWJpdCBSb290IENBMSUwIwYJKoZIhvcNAQkBFhZzZWN1cml0
      eUBlcnVkaWNpdHkuY29tghRKGa+dWSEQ5dbjKBFBvpznkkKKHDAbBgNVHREEFDAS
      ghBkaWVnby5yaXZlcmEucHJ2MA0GCSqGSIb3DQEBCwUAA4IBAQBljFxOAOgYaqbk
      /3GCXhLxFxtEeDImUkywfPkoeuwauanqIU4I5Ba/BH3xd2Syn70Kt0PY6457bl5Q
      IqhW0nmfUz1Ae2tmNryBBCcWfn+iw6Gi8dvcD0Ye2LJCcUqaph5KLgcV5lI16pBq
      ZVZSG0Rc4KBuqxe9pdedysu4AT1dhqAuqzUUGc0gGOniFIgNUuFyMGrQWmpZ8eZl
      DyoOqTwmFPeKNa31eS2bEp4FWM2QEythetrfL0FakGeZ2czkZy6AKJNoo2sUbnGB
      u/FTrXGbo4CM7pNEPfQyILPNv/iN8eCR19ZeeZEWvKu9NCJJ5tCtDPr3ZZqVDd03
      Wqj5ONAY
      -----END CERTIFICATE-----

  # serverAdmin: "server.admin.for@ssl.server"
  # documentRoot: "/document/root/for/the/SSL/server"
  # logLevel: "info ssl:warn"
  # client:
  #   verify: require
  #   depth: 10
  # options:
  #   - +FakeBasicAuth
  #   - +ExportCertData
  #   - +StrictRequire
  # sections:
  #   filesMatch: |
  #     <FilesMatch "\.(cgi|shtml|phtml|php)$">
  #       SSLOptions +StdEnvVars
  #     </FilesMatch>
  #   directory: |
  #     <Directory /usr/lib/cgi-bin>
  #       SSLOptions +StdEnvVars
  #     </Directory>
  #   browserMatch: |
  #     BrowserMatch "MSIE [2-6]" \
  #     nokeepalive ssl-unclean-shutdown \
  #     downgrade-1.0 force-response-1.0
  #   other: |
  #     ... other sections that are needed go here ...
  # module:
  #   randomSeed:
  #     - startup builtin
  #     - startup file:/dev/urandom 512
  #     - connect builtin
  #     - connect file:/dev/urandom 512
  #   addType:
  #     - application/x-x509-ca-cert .crt
  #     - application/x-pkcs7-crl .crl
  #   passPhraseDialog: exec:/usr/share/apache2/ask-for-passphrase
  #   sessionCache:
  #     engine: shmcb:${APACHE_RUN_DIR}/ssl_scache(512000)
  #     timeout: 300
  #   mutex: file:${APACHE_LOCK_DIR}/ssl_mutex ssl-cache
  #   cipherSuite: HIGH:!aNULL
  #   honorCipherOrder: on
  #   protocol:
  #     - all
  #     - -SSLv3
  #   insecureRenegotiation: On
  #   strictSNIVHostCheck: On

#
# Use the module's name here. I.e. for mod_proxy, use "proxy", etc.
#
modules:
  # The key is the module name (unless "trueName" is used), and
  # the value can either be an instruction to add the module (via
  # the words "add", "enable", "enabled", "on", "true", "yes", "y"), or
  # an instruction to remove the module if it's enabled (via the words
  # "remove", "delete",  "off", "disabled", "disable", "false", "no", "n").
  #
  # Any other content will be interpreted as the contents of the module's
  # "conf" file, and will be used as such.
  alias: add

  # If using a map, the keys are the extensions of the files that need
  # to be created, and the values are their contents. You can use inc:...
  # here as well if you wish to bring the contents in from another file.
  #
  # The special case is the key "enabled" which is a boolean (true/false)
  # which controls whether the configuration for the module should be
  # applied (true) or not (false).
  auth_basic:
    enabled: true
    load: |
      # This is example load data for auth_basic
      # Depends: authn_core
      LoadModule auth_basic_module /usr/lib/apache2/modules/mod_auth_basic.so
    conf: |
      # This is example configuration data for auth_basic
      # this file isn't used, it's just added as a demonstrator
    crap: |
      # This is example crap file for auth_basic
      # this file isn't used, it's just added as a demonstrator
  autoindex: remove
  dir: |
    # This file came from the config.yaml file
    <IfModule mod_dir.c>
    DirectoryIndex index.html index.cgi index.pl index.php index.xhtml index.htm
    </IfModule>
  weird-name-1:
    enabled: false
  weird-name-2:
    trueName: ssl
    enabled: true
  ssl: this should break and be ignored because the "trueName" ssl is in use

# This section works simliar to the modules in every respect, except that the
# configurations go into sites-enabled
#
# sites:
#   site-1: boolean
#   site-2:
#     enabled: boolean
#     conf: |
#       contents of the site configuration
#   # ...
#   site-N: ...

# This section works simliar to the modules and sites in every respect, except
# that the configurations go into conf-enabled
#
# confs:
#   conf-1: add/remove/etc
#   conf-2:
#     enabled: true/false
#     conf: |
#       contents of the additional configuration
#   # ...
#   conf-N: inc:...
```

The intent behind using this simplified configuration model is to allow flexibility to simply enable/disable modules rapidly, as well as more complex configuration if desired.  There are few limitations to what can be achieved using this configuration model.
