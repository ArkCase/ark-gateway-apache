#!/usr/bin/env /usr/bin/python3
#

#
# Import the base libraries
#
#import datetime
#import grp
import os
#import pwd
import re
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

TRUE_VALUES  = dict.fromkeys(["true",  "yes", "y", "1", "on",  "enabled",  "enable" ], True)
FALSE_VALUES = dict.fromkeys(["false", "no",  "n", "0", "off", "disabled", "disable"], False)

OPENSSL_EXE = "/usr/bin/openssl"
GUCCI_EXE = "/usr/local/bin/gucci"

SSL_GID = os.environ["SSL_GID"]
SSL_DIR = "/ssl"

PATH_CERT = SSL_DIR + "/cert.pem"
CERT_HEADER = "-----BEGIN CERTIFICATE-----"
PATH_KEY = SSL_DIR + "/key.pem"
KEY_HEADER = "-----BEGIN PRIVATE KEY-----"
PATH_CA = SSL_DIR + "/ca.pem"
PATH_CRL = SSL_DIR + "/crl.pem"

APACHE_DIR = "/etc/apache2"

CONF_AVAILABLE = APACHE_DIR + "/conf-available"
CONF_ENABLED = APACHE_DIR + "/conf-enabled"

MODS_AVAILABLE = APACHE_DIR + "/mods-available"
MODS_ENABLED = APACHE_DIR + "/mods-enabled"

SITES_AVAILABLE = APACHE_DIR + "/sites-available"
SITES_ENABLED = APACHE_DIR + "/sites-enabled"

SSL_TEMPLATE = APACHE_DIR + "/default-ssl.conf.tpl"
SSL_TEMPLATE_TARGET = SITES_ENABLED + "/default-ssl.conf"

INC_PARSER = re.compile("^inc:(/.+)$")

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

def listAvailable(src, ext):
	if not ext or not src:
		return []

	if not isinstance(ext, TYPE_LIST):
		ext = str(ext).split(",")

	ret = []
	for f in os.listdir(src):
		p = src + "/" + f
		if os.path.isfile(p):
			for e in ext:
				e = "." + e
				if f.endswith(e):
					ret += [f.removesuffix(e)]

	ret = list(set(ret))
	ret.sort()
	return ret

def processLinkDirectory(general, name, data, available, enabled, mainExt, extraExt = [], extraRequired = False):
	# First things first - make sure that the requested configuration is viable
	# available = dict.fromkeys(listAvailable(available, extensions), True)
	reqMain = dict.fromkeys(listAvailable(available, mainExt), True)
	reqExtra = dict.fromkeys(listAvailable(available, extraExt), True)

	missing = []
	simpleLinks = []
	includes = {}
	generations = {}
	for key in data:
		value = data[key]

		# First things first: is this value a string?
		if isinstance(value, TYPE_STRING):
			# Is this a boolean-value?
			if TRUE_VALUES.get(value.lower()):
				# This is a boolean-value, so stow it to create the link(s)
				# to the available file(s) into the target as needed
				simpleLinks += [key]
				continue

			# Is it an include?
			m = INC_PARSER.match(value)
			if m:
				# It's an include! Validate that the path exists,
				# and refers to a regular file that is readable,
				# and stow it for inclusion into the target
				includes[key] = { mainExt : m.group(1) }
				continue

			# This must be the contents of the main file, so
			# stow it for storage into the target
			generations[key] = { mainExt : value }
			continue

		# If it's a dictionary, then it must be the "longform" structure
		if isinstance(value, TYPE_DICT):

			# First things first: is it enabled?
			enabled = value.pop("enabled", "true")
			enabled = TRUE_VALUES.get(str(enabled).lower())

			# If it's not enabled, simply skip it and do nothing
			if not enabled:
				continue

			# It's enabled, so process the contents
			files = values.get("files")
			if files is None:
				# No files defined, so treat it as a simple include
				simpleLinks += [key]
				continue

			if not isinstance(files, TYPE_DICT):
				fail("The 'files:' sections must be dictionaries whose keys are the files' extensions to be created (%s %s)" % (name, key))

			# We have files to create, so stow them for creation
			for ext in files:
				value = str(files[ext])

				# Is it an include?
				m = INC_PARSER.match(value)
				if m:
					# It's an include! Validate that the path exists,
					# and refers to a regular file that is readable,
					# and stow it for inclusion into the target
					includes[key] = { ext : m.group(1) }
					continue

				# This must be the contents of the main file, so
				# stow it for storage into the target
				generations[key] = { ext : value }
				continue

			continue

		fail("Invalid format for the %s.%s section - wasn't a string, nor the longform dict" % (name, key))

	# Ok, so at this point...
	#   * simpleLinks contains the list of names for whom all files will just be
	#     linked from available into enabled. Missing sources are an error
	#
	#   * includes contains a dict whose keys are the name of the object to be
	#     created/linked, and the value is a dict whose keys are the file extensions
	#     to be created, with the value being the file whose contents should be stored there.
	#     If there's a missing extension from the ones listed, then a simple link must be possible
	#     from available into enabled. Missing sources are an error
	#
	#   * generations contains a dict whose keys are the name of the object to be
	#     created, and the value is a dict whose keys are the file extensions
	#     to be created, with the value being the contents of the files that need creating.
	#     If there's a missing extension from the ones listed, then a simple link must be possible
	#     from available into enabled. Missing sources are an error
	#
	# The next step is to validate that all these operations would succeed, and start accumulating the lambdas
	# that will perform the actual work at the very end once the entire configuration is validated
	print("simpleLinks for %s: %s" % (name, str(simpleLinks)))
	print("includes for %s: %s" % (name, str(includes)))
	print("generations for %s: %s" % (name, str(generations)))

def processModules(general, modules):
	print("Processing the module configurations")
	return processLinkDirectory(general, "modules", modules, MODS_AVAILABLE, MODS_ENABLED, "conf", "load", True)

def processSites(general, sites):
	print("Processing the site configurations")
	return processLinkDirectory(general, "sites", sites, SITES_AVAILABLE, SITES_ENABLED, "conf", [])

def processConfs(general, confs):
	print("Processing the additional configurations")
	return processLinkDirectory(general, "confs", confs, CONF_AVAILABLE, CONF_ENABLED, "conf", [])

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
