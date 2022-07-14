<IfModule mod_ssl.c>

	# Pseudo Random Number Generator (PRNG):
	# Configure one or more sources to seed the PRNG of the SSL library.
	# The seed data should be of good random quality.
	# WARNING! On some platforms /dev/random blocks if not enough entropy
	# is available. This means you then cannot use the /dev/random device
	# because it would lead to very long connection times (as long as
	# it requires to make more entropy available). But usually those
	# platforms additionally provide a /dev/urandom device which doesn't
	# block. So, if available, use this one instead. Read the mod_ssl User
	# Manual for more details.
	#
	{{- $randomSeed := (coalesce ((.ssl).module).randomSeed (list "startup builtin" "startup file:/dev/urandom 512" "connect builtin" "connect file:/dev/urandom 512")) -}}
	{{- range $randomSeed }}
	SSLRandomSeed {{ . }}
	{{- end }}

	##
	##  SSL Global Context
	##
	##  All SSL configuration in this context applies both to
	##  the main server and all SSL-enabled virtual hosts.
	##

	#
	#   Some MIME-types for downloading Certificates and CRLs
	#
	{{- $addType := (coalesce ((.ssl).module).addType (list "application/x-x509-ca-cert .crt" "application/x-pkcs7-crl .crl")) -}}
	{{- range $addType }}
	AddType {{ . }}
	{{- end }}

	#   Pass Phrase Dialog:
	#   Configure the pass phrase gathering process.
	#   The filtering dialog program (`builtin' is a internal
	#   terminal dialog) has to provide the pass phrase on stdout.
	SSLPassPhraseDialog  {{ coalesce ((.ssl).module).passPhraseDialog "exec:/usr/share/apache2/ask-for-passphrase" }}

	#   Inter-Process Session Cache:
	#   Configure the SSL Session Cache: First the mechanism 
	#   to use and second the expiring timeout (in seconds).
	#   (The mechanism dbm has known memory leaks and should not be used).
	#SSLSessionCache		 dbm:${APACHE_RUN_DIR}/ssl_scache
	SSLSessionCache			{{ coalesce (((.ssl).module).sessionCache).engine "shmcb:${APACHE_RUN_DIR}/ssl_scache(512000)" }}
	SSLSessionCacheTimeout  {{ int (coalesce (((.ssl).module).sessionCache).timeout "300") }}

	#   Semaphore:
	#   Configure the path to the mutual exclusion semaphore the
	#   SSL engine uses internally for inter-process synchronization. 
	#   (Disabled by default, the global Mutex directive consolidates by default
	#   this)
	{{- if ((.ssl).module).mutex }}
	Mutex {{ .ssl.module.mutex }}
	{{- else }}
	#Mutex file:${APACHE_LOCK_DIR}/ssl_mutex ssl-cache
	{{- end }}


	#   SSL Cipher Suite:
	#   List the ciphers that the client is permitted to negotiate. See the
	#   ciphers(1) man page from the openssl package for list of all available
	#   options.
	#   Enable only secure ciphers:
	SSLCipherSuite {{ coalesce ((.ssl).module).cipherSuite "HIGH:!aNULL" }}

	# SSL server cipher order preference:
	# Use server priorities for cipher algorithm choice.
	# Clients may prefer lower grade encryption.  You should enable this
	# option if you want to enforce stronger encryption, and can afford
	# the CPU cost, and did not override SSLCipherSuite in a way that puts
	# insecure ciphers first.
	# Default: Off
	SSLHonorCipherOrder {{ coalesce ((.ssl).module).honorCipherOrder "Off" }}

	#   The protocols to enable.
	#   Available values: all, SSLv3, TLSv1, TLSv1.1, TLSv1.2
	#   SSL v2  is no longer supported
	{{- $protocol := (coalesce ((.ssl).module).protocol (list "all" "-SSLv3")) -}}
	SSLProtocol {{- range $protocol }} {{ . }}{{- end }}

	#   Allow insecure renegotiation with clients which do not yet support the
	#   secure renegotiation protocol. Default: Off
	SSLInsecureRenegotiation {{ coalesce ((.ssl).module).insecureRenegotiation "Off" }}

	#   Whether to forbid non-SNI clients to access name based virtual hosts.
	#   Default: Off
	SSLStrictSNIVHostCheck {{ coalesce ((.ssl).module).strictSNIVHostCheck "Off" }}

	#
	# Extra settings lines added in the module configuration
	#
	{{- range ((.ssl).module).extraSettings }}
	{{ . }}
	{{- end }}
	#
	# End extra settings
	#

</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
