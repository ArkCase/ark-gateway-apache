#!/usr/bin/env /usr/bin/python3
#

#
# Import the base libraries
#
#import datetime
#import grp
import os
#import pwd
#import re
import shutil
#import stat
import ssl
import subprocess
import sys
import tempfile
#import time
#import traceback

TYPE_LIST = type([])
TYPE_STRING = type("")
TYPE_DICT = type({})

TRUE_VALUES = { "true" : True, "yes" : True, "y" : True, "1" : True, "on" : True, "enabled" : True, "enable" : True }

OPENSSL_EXE = "/usr/bin/openssl"
GUCCI_EXE = "/usr/local/bin/gucci"
PATH_CERT = "/ssl/cert.pem"
CERT_HEADER = "-----BEGIN CERTIFICATE-----"
PATH_KEY = "/ssl/key.pem"
KEY_HEADER = "-----BEGIN PRIVATE KEY-----"
PATH_CA = "/ssl/ca.pem"
PATH_CRL = "/ssl/crl.pem"
SSL_TEMPLATE = "/etc/apache2/default-ssl.conf.tpl"
SSL_TEMPLATE_TARGET = "/etc/apache2/sites-enabled/default-ssl.conf"

SSL_GID = os.environ["SSL_GID"]

#
# Import the YAML library
#
from yaml import load, dump
try:
	from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
	from yaml import Loader, Dumper

#
# Set the debug mode
#
DEBUG = False
try:
	d = os.environ["DEBUG"].lower()
	if TRUE_VALUES.get(d):
		DEBUG = True
except KeyError:
	# Do nothing - stick to the default value
	pass

def debug(msg, *args):
	if not DEBUG:
		return None
	print(msg % args)

#
# Set the dry run mode
#
DRY_RUN = False
try:
	dr = os.environ["DRY_RUN"].lower()
	if TRUE_VALUES.get(dr):
		DRY_RUN = True
		DEBUG = True
		debug("WARNING: Dry run mode active")
except KeyError:
	# Do nothing - stick to the default value
	pass

class InvalidPEMFile(Exception):
	pass

class PathNotAbsolute(Exception):
	pass

class NotAFileError(Exception):
	pass

class InvalidModule(Exception):
	pass

class MissingModule(Exception):
	pass

class InvalidSite(Exception):
	pass

class MissingSite(Exception):
	pass

class InvalidConfig(Exception):
	pass

class MissingConfig(Exception):
	pass

class InvalidCertificate(Exception):
	pass

class InvalidCertificateKey(Exception):
	pass

class InvalidCertificationAuthority(Exception):
	pass

def fail(message, exitCode = 1):
	print(message)
	sys.exit(exitCode)

if len(sys.argv) < 2:
	fail("usage: %s config-file" % sys.argv[0])

CONFIG = sys.argv[1]
if not os.path.exists(CONFIG):
	fail("Configuration file [%s] does not exist" % CONFIG)
if not os.path.isfile(CONFIG):
	fail("The path [%s] does refer to a regular file" % CONFIG)

try:
	document = open(CONFIG)
except Exception as e:
	fail("Failed to open the configuration from [%s]: %s" % (CONFIG, str(e)))

try:
	yamlData = load(document, Loader=Loader)

	if yamlData is None:
		print("No configuration data loaded from [%s]" % (CONFIG))
		sys.exit(0)

	if not isinstance(yamlData, TYPE_DICT):
		fail("Bad YAML structure - must produce a dict:\n%s" % (yamlData))
except Exception as e:
	msg = ""
	if hasattr(e, 'problem_mark'):
		mark = e.problem_mark
		msg = "YAML syntax error in the configuration data at line %s, column %s of [%s]" % (mark.line + 1, mark.column + 1, CONFIG)
	else:
		msg = "Failed to parse the YAML data from [%s]" % (str(e), CONFIG)
	fail(msg)
finally:
	# Clean up if necessary
	if not isinstance(document, TYPE_STRING):
		document.close()

def ensurePEMValid(value, asKey=False):
	# The value must either be a PEM-encoded certificate, or an
	# absolute path to one
	header = CERT_HEADER
	if asKey:
		header = KEY_HEADER

	path = value
	if value.strip().startswith(header):
		# First things first, dump the contents into a temp file
		(handle, path) = tempfile.mkstemp()
		with os.fdopen(handle, "w") as out:
			out.write(value)

		try:
			command = [OPENSSL_EXE, "x509", "-text", "-noout", "-in", path]
			if asKey:
				command = [OPENSSL_EXE, "rsa", "-in", path, "-check"]
			subprocess.check_output(command)
		except CalledProcessError as e:
			# The file does not contain the PEM-encoded crap we seek. Thus, assume
			# the given value MUST be a file, and thus delete the temporary file
			os.remove(path)
			objType = "certificate"
			if asKey:
				objType = "private key"
			raise InvalidPEMFile("The given data does not contain a valid PEM-encoded %s (rc = %d):\n%s\n\n%s" % (objType, e.returncode, e.output, value))
	else:
		# This is not a certificate, so it's a path. It must be absolute, exist,
		# refer to a regular file, and the file must be readable
		if not os.path.isabs(path):
			raise PathNotAbsoulte("The given path [%s] is not absolute" % (path))

		if not os.path.exists(path):
			raise FileNotFoundError("The file [%s] does not exist" % (path))

		if not os.path.isfile(path):
			raise NotAFileError("The path [%s] does not refer to a regular file" % (path))

		if not os.access(path, os.R_OK):
			raise PermissionError("The file [%s] is not readable" % (path))

	# The file exists, is a regular file, and is readable
	return os.path.realpath(path)

def processModules(general, section):
	print("Processing the module configurations")

def processSites(general, section):
	print("Processing the site configurations")

def processConfs(general, section):
	print("Processing the additional configurations")

def renderSsl(general, ssl):
	print("Processing the SSL configuration")
	cert = ssl.get("cert")
	key = ssl.get("key")

	if cert and key:
		# Ok we have a certificate and a key, so put them
		# in /ssl/cert.pem and /ssl/key.pem respectively
		try:
			cert = ensurePEMValid(cert)
			if cert != PATH_CERT:
				shutil.copy(cert, PATH_CERT)
		except Exception as e:
			fail("The given certificate is not valid: %s" % (str(e)))

		try:
			key = ensurePEMValid(key, True)
			if key != PATH_KEY:
				shutil.copy(key, PATH_KEY)
		except Exception as e:
			fail("The given private key is not valid: %s" % (str(e)))
	else:
		# If not all the settings are given, we check to see if the
		# default files exist, and use those automatically
		hasCert = True
		try:
			if not cert:
				cert = PATH_CERT
			cert = ensurePEMValid(cert)
			if cert != PATH_CERT:
				shutil.copy(cert, PATH_CERT)
		except FileNotFoundError:
			# If the file isn't there, we're good so far
			hasCert = False

		hasKey = True
		try:
			if not key:
				key = PATH_KEY
			key = ensurePEMValid(key)
			if key != PATH_KEY:
				shutil.copy(key, PATH_KEY)
		except FileNotFoundError:
			# If the file isn't there, we're good so far
			hasKey = False

		# If we have one but not the other, we can't go on...
		if hasCert != hasKey:
			fail("Cannot configure SSL properly - you must provide both the certificate (/ssl/cert.pem) and key (/ssl/key.pem) files")

		# Here we know either both are equally valid, or equally invalid
		if not hasCert:
			# If neither file exists, just ignore SSL configuration
			print("No certificate information found - cannot configure SSL")
			return

	print("Certificate and Private Key are ready, setting the correct permissions")

	# Set the correct permissions for the certificate
	os.chmod(PATH_CERT, 0o644)
	shutil.chown(PATH_CERT, "root", SSL_GID)

	# Set the correct permissions for the private key
	os.chmod(PATH_KEY, 0o640)
	shutil.chown(PATH_KEY, "root", SSL_GID)

	# Now compute the Certification Authorities
	print("Rendering the CA lists into [%s]" % (PATH_CRL))
	newCa = []
	ca = ssl.get("ca")
	if ca:
		for v in ca:
			newCa += [ensurePEMValid(v)]
	ca = newCa
	if len(ca) > 0:
		(handle, outPath) = tempfile.mkstemp()
		try:
			with os.fdopen(handle, "w") as out:
				for v in ca:
					with open(v, 'r') as src:
						for line in src:
							out.write(line)
		except Exception as e:
			fail("Failed to concatenate the CA files from %s: %s" % (ca, str(e)))

		# All is well, so copy the concatenated file into the target
		shutil.move(outPath, PATH_CA)
		os.chmod(PATH_CA, 0o644)
		shutil.chown(PATH_CA, "root", SSL_GID)
	else:
		print("No CA list given, clearing out the existing one")
		try:
			os.remove(PATH_CA)
		except FileNotFoundError:
			pass

	# Now compute the Certificate Revocation Lists
	print("Rendering the CRL lists into [%s]" % (PATH_CRL))
	newCrl = []
	crl = ssl.get("crl")
	if crl:
		for v in crl:
			newCrl += [ensurePEMValid(v)]
	crl = newCrl
	if len(crl) > 0:
		(handle, outPath) = tempfile.mkstemp()
		try:
			with os.fdopen(handle, "w") as out:
				for v in crl:
					with open(v, 'r') as src:
						for line in src:
							out.write(line)
		except Exception as e:
			fail("Failed to concatenate the CRL files from %s: %s" % (ca, str(e)))

		# All is well, so copy the concatenated file into the target
		shutil.move(outPath, PATH_CRL)
		os.chmod(PATH_CRL, 0o644)
		shutil.chown(PATH_CRL, "root", SSL_GID)
	else:
		print("No CRL list given, clearing out the existing one")
		try:
			os.remove(PATH_CRL)
		except FileNotFoundError:
			pass

	# Finally, render the SSL site template file
	print("Rendering the SSL configuration into [%s]" % (SSL_TEMPLATE_TARGET))
	try:
		os.remove(SSL_TEMPLATE_TARGET)
	except FileNotFoundError:
		pass
	(handle, outPath) = tempfile.mkstemp()
	with os.fdopen(handle, "w") as out:
		result = subprocess.run([GUCCI_EXE, "-o", "missingkey=zero", "-f", CONFIG, SSL_TEMPLATE], stdout=out)
		if result.returncode != 0:
			fail("Failed to render the SSL configuration template: %s" % (result.stderr))

	os.chmod(outPath, 0o644)
	shutil.chown(outPath, "root", "root")
	shutil.move(outPath, SSL_TEMPLATE_TARGET)

sections = []
sections += [( "modules", "modules",    processModules )]
sections += [( "sites",   "sites",      processSites   )]
sections += [( "confs",   "additional", processConfs   )]
sections += [( "ssl",     "SSL",        renderSsl     )]

general = {}
for key, label, function in sections:
	try:
		data = yamlData[key]
		try:
			function(general, data)
		except Exception as e:
			fail("Failed to process the %s configurations from [%s]: %s" % (label, CONFIG, str(e)))
	except KeyError:
		print("No %s configurations found in [%s]" % (label, CONFIG))

print("Configurations applied per [%s]" % (CONFIG))
sys.exit(0)
