#!/usr/bin/env /usr/bin/python3
#

#
# Import the base libraries
#
import datetime
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
import traceback

TYPE_LIST = type([])
TYPE_STRING = type("")
TYPE_DICT = type({})

TRUE_VALUES  = dict.fromkeys(["true",  "yes", "y", "1", "on",  "enabled",  "enable" ], True)
FALSE_VALUES = dict.fromkeys(["false", "no",  "n", "0", "off", "disabled", "disable"], False)

# First things first: create the directory where this configuration will be stored, and
# extract the template TAR file onto it.

APACHE2CTL_EXE = "/usr/sbin/apache2ctl"
GUCCI_EXE = "/usr/local/bin/gucci"
OPENSSL_EXE = "/usr/bin/openssl"
TAR_EXE = "/usr/bin/tar"

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

CONF_DIR = "/conf"
BACKUP_DIR = CONF_DIR + "/.backups"

WORK_ROOT = "/work"
WORK_TMP = WORK_ROOT + "/.tmp"
TEMPLATE_DIR = WORK_ROOT + "/templates"
DEFAULTS_TAR_GZ = WORK_ROOT + "/defaults.tar.gz"
WORK_DIR = tempfile.mkdtemp(prefix="apache2." + TIMESTAMP + ".", dir=WORK_TMP)

APACHE_DIR = "/etc/apache2"

SSL_GID = os.environ["SSL_GID"]
SSL_DIR = WORK_DIR + "/ssl"

PATH_CERT = SSL_DIR + "/cert.pem"
PATH_KEY = SSL_DIR + "/key.pem"
PATH_CA = SSL_DIR + "/ca.pem"
PATH_CRL = SSL_DIR + "/crl.pem"

CONF_AVAILABLE = WORK_DIR + "/conf-available"
CONF_ENABLED = WORK_DIR + "/conf-enabled"

MODS_AVAILABLE = WORK_DIR + "/mods-available"
MODS_ENABLED = WORK_DIR + "/mods-enabled"

SITES_AVAILABLE = WORK_DIR + "/sites-available"
SITES_ENABLED = WORK_DIR + "/sites-enabled"

SSL_TEMPLATE_TARGET = "default-ssl.conf"
SSL_TEMPLATE = TEMPLATE_DIR + "/" + SSL_TEMPLATE_TARGET + ".tpl"
SSL_TEMPLATE_TARGET = SITES_ENABLED + "/" + SSL_TEMPLATE_TARGET

MAIN_TEMPLATE_TARGET = "apache2.conf"
MAIN_TEMPLATE = TEMPLATE_DIR + "/" + MAIN_TEMPLATE_TARGET + ".tpl"
MAIN_TEMPLATE_TARGET = WORK_DIR + "/" + MAIN_TEMPLATE_TARGET

MAIN_WEB_TEMPLATE_TARGET = "000-default.conf"
MAIN_WEB_TEMPLATE = TEMPLATE_DIR + "/" + MAIN_WEB_TEMPLATE_TARGET + ".tpl"
MAIN_WEB_TEMPLATE_TARGET = SITES_ENABLED + "/" + MAIN_WEB_TEMPLATE_TARGET

INC_PARSER = re.compile("^inc:(.+)$")

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
	DEBUG = TRUE_VALUES.get(os.environ["DEBUG"].lower())
except KeyError:
	# Do nothing - stick to the default value
	pass

def debug(msg, *args):
	if not DEBUG:
		return None
	print(msg % args)

def strExc(e):
	if DEBUG:
		return traceback.format_exc(e)
	return str(e)

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
	fail("Failed to open the configuration from [%s]: %s" % (CONFIG, strExc(e)))

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
		msg = "Failed to parse the YAML data from [%s]" % (strExc(e), CONFIG)
	fail(msg)
finally:
	# Clean up if necessary
	if not isinstance(document, TYPE_STRING):
		document.close()

def testConfig(directory):
	try:
		subprocess.check_output([APACHE2CTL_EXE, "-t", "-d", directory], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		raise InvalidConfig(str(e.output))

def copyToTemp(src):
	(handle, path) = tempfile.mkstemp()
	with os.fdopen(handle, "w") as out:
		pass
	shutil.copy(src, path)
	return path

def writeToFile(data, target=None, mode=None, user=None, group=None):
	handle = None
	if target is None:
		(handle, target) = tempfile.mkstemp()

	try:
		if handle:
			with os.fdopen(handle, "w") as out:
				out.write(data)
		else:
			with open(target, "w") as out:
				out.write(data)
	except Exception as e:
		try:
			os.remove(target)
		except Exception:
			# We're fine ...
			pass
		finally:
			# Punt the exception upward
			raise e

	if mode:
		os.chmod(target, mode)

	if user or group:
		shutil.chown(target, user, group)

	return target

def concatToTarget(sources, target=None, mode=None, user=None, group=None):
	(handle, path) = tempfile.mkstemp()
	try:
		with os.fdopen(handle, "w") as out:
			for s in sources:
				with open(s, 'r') as src:
					for line in src:
						out.write(line)
	except Exception as e:
		try:
			os.remove(path)
		except FileNotFoundError:
			# We're fine ...
			pass
		finally:
			# Punt the exception upward
			raise e

	if target:
		shutil.move(path, target)
	else:
		target = path

	if mode:
		os.chmod(target, mode)

	if user or group:
		shutil.chown(target, user, group)

	return target

def copyOrCreate(value, target=None, mode=None, user=None, group=None):
	path = value
	m = INC_PARSER.match(value)
	if m:
		# It's an include! Validate that the path exists, and refers to a regular
		# file that is readable
		path = m.group(1)
		srcPath = path

		# Make sure the path never overflows
		path = os.path.normpath("/" + path)[1:]
		path = CONF_DIR + "/" + path

		# The path must exist, refer to a regualr file, and the file
		# must be readable.

		if not os.path.exists(path):
			raise FileNotFoundError("The file [%s] does not exist (%s)" % (srcPath, path))

		if not os.path.isfile(path):
			raise NotAFileError("The path [%s] does not refer to a regular file (%s)" % (srcPath, path))

		if not os.access(path, os.R_OK):
			raise PermissionError("The file [%s] is not readable (%s)" % (srcPath, path))

		if target is None:
			path = copyToTemp(path)
		else:
			shutil.copy(path, target)
			path = target
	else:
		path = writeToFile(value, target)

	if mode:
		os.chmod(path, mode)

	if user or group:
		shutil.chown(path, user, group)

	return { "path" : os.path.realpath(path), "included" : (m is not None) }

def ensurePEMValid(value, target=None, asKey=False, mode=None, user=None, group=None):
	# Verify that the file's contents are a PEM-encoded "something" (cert or key)
	info = copyOrCreate(value, target, mode, user, group)
	try:
		command = [OPENSSL_EXE, "x509", "-text", "-noout", "-in", info["path"]]
		if asKey:
			command = [OPENSSL_EXE, "rsa", "-in", info["path"], "-check"]
		subprocess.check_output(command)
	except subprocess.CalledProcessError as e:
		# The file does not contain the PEM-encoded crap we seek. Thus, assume
		# the given value MUST be a file, and thus delete the temporary file
		if info["included"]:
			description = "file at [%s]" % (value)
		else:
			description = "given data"

		# Remove the temporary file
		os.remove(info["path"])

		objType = "certificate"
		if asKey:
			objType = "private key"

		raise InvalidPEMFile("The %s does not contain a valid PEM-encoded %s (rc = %d):\n%s" % (description, objType, e.returncode, e.output))

	return info["path"]

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

def clearLinkDirectory(general, label, directory):
	print("Clearing the %s directory at [%s]" % (label, directory))
	for f in os.listdir(directory):
		p = os.path.join(directory, f)
		if os.path.isfile(file_path) or os.path.islink(file_path):
			os.unlink(file_path)
		elif os.path.isdir(file_path):
			shutil.rmtree(file_path)

def clearModules(general):
	return clearLinkDirectory(general, "module", MODS_ENABLED)

def processModules(general, modules):
	print("Processing the module configurations")
	return processLinkDirectory(general, "modules", modules, MODS_AVAILABLE, MODS_ENABLED, "conf", "load", True)

def clearSites(general):
	return clearLinkDirectory(general, "site", MODS_ENABLED)

def processSites(general, sites):
	print("Processing the site configurations")
	return processLinkDirectory(general, "sites", sites, SITES_AVAILABLE, SITES_ENABLED, "conf", [])

def clearConfs(general):
	return clearLinkDirectory(general, "additional", MODS_ENABLED)

def processConfs(general, confs):
	print("Processing the additional configurations")
	return processLinkDirectory(general, "confs", confs, CONF_AVAILABLE, CONF_ENABLED, "conf", [])

def renderTemplate(label, template, target, user=None, group=None, mode=None):
	print("Rendering the %s configuration into [%s]" % (label, target))
	try:
		os.remove(target)
	except FileNotFoundError:
		pass

	with open(target, "w") as out:
		try:
			subprocess.run([GUCCI_EXE, "-o", "missingkey=zero", "-f", CONFIG, template], stdout=out).check_returncode()
		except subprocess.CalledProcessError as e:
			fail("Failed to render the %s configuration template: %s" % (label, e.output))

	if mode:
		os.chmod(target, mode)

	if user or group:
		shutil.chown(target, user, group)

	return target

def renderSsl(general, ssl):
	print("Processing the SSL configuration")
	cert = ssl.get("cert")
	key = ssl.get("key")

	if not cert and not key:
		print("No certificate information found - cannot configure SSL")
		return

	if not cert or not key:
		fail("Cannot configure SSL properly - you must provide both the certificate and key files or data")

	if not os.path.exists(SSL_DIR):
		os.mkdir(SSL_DIR, mode=0o750)
		shutil.chown(SSL_DIR, "root", SSL_GID)

	# Ok we have a certificate and a key, so put them
	# in PATH_CERT and PATH_KEY respectively
	try:
		ensurePEMValid(cert, PATH_CERT, mode=0o644, user="root", group=SSL_GID)
	except Exception as e:
		fail("The given certificate is not valid: %s" % (strExc(e)))

	try:
		ensurePEMValid(key, PATH_KEY, True, mode=0o640, user="root", group=SSL_GID)
	except Exception as e:
		fail("The given private key is not valid: %s" % (strExc(e)))

	# Now compute the Certification Authorities
	print("Rendering the CA lists into [%s]" % (PATH_CA))
	newCa = []
	ca = ssl.get("ca")
	if ca:
		for v in ca:
			newCa += [ensurePEMValid(v)]
	ca = newCa
	if len(ca) > 0:
		try:
			concatToTarget(ca, PATH_CA, user="root", group=SSL_GID, mode=0o644)
		except Exception as e:
			fail("Failed to concatenate the CA files from %s: %s" % (ca, strExc(e)))
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
		try:
			concatToTarget(crl, PATH_CRL, user="root", group=SSL_GID, mode=0o644)
		except Exception as e:
			fail("Failed to concatenate the CRL files from %s: %s" % (ca, strExc(e)))
	else:
		print("No CRL list given, clearing out the existing one")
		try:
			os.remove(PATH_CRL)
		except FileNotFoundError:
			pass

	renderTemplate("SSL", SSL_TEMPLATE, SSL_TEMPLATE_TARGET, "root", "root", 0o644)

def renderMain(general, ssl):
	renderTemplate("main", MAIN_TEMPLATE, MAIN_TEMPLATE_TARGET, "root", "root", 0o644)
	renderTemplate("website", MAIN_WEB_TEMPLATE, MAIN_WEB_TEMPLATE_TARGET, "root", "root", 0o644)

sections = []
sections += [( "modules", "modules",    processModules, clearModules )]
sections += [( "sites",   "sites",      processSites,   clearSites   )]
sections += [( "confs",   "additional", processConfs,   clearConfs   )]
sections += [( "ssl",     "SSL",        renderSsl,      None         )]
sections += [( "main",    "main",       renderMain,     None         )]

# First things first - extract the TAR file into the work directory
try:
	subprocess.check_output([TAR_EXE, "-C", WORK_DIR, "-xzvf", DEFAULTS_TAR_GZ])
except subprocess.CalledProcessError as e:
	fail("Failed to extract the configuration defaults (rc = %d): %s" % (e.returncode, e.output))

general = {}
work = {}
for key, label, processor, clearer in sections:
	try:
		data = yamlData[key]

		if not data:
			continue

		clear = data.pop("clearDefaults", "false")
		if TRUE_VALUES.get(str(clear).lower()) and clearer:
			clearer(general)

		try:
			work[key] = { "label" : label, "result" : processor(general, data) }
		except Exception as e:
			fail("Failed to process the %s configurations from [%s]: %s" % (label, CONFIG, strExc(e)))

	except KeyError:
		print("No %s configurations found in [%s]" % (label, CONFIG))

print("Configurations applied per [%s]" % (CONFIG))

# Now, validate the configurations
try:
	testConfig(WORK_DIR)
except InvalidConfig as e:
	fail("The configuration was applied successfully, but Apache did not validate it:\n%s" % (strExc(e)))

print("Configurations successfully verified!")
WORK_DIR = os.path.realpath(WORK_DIR)
if os.path.exists(APACHE_DIR):
	try:
		os.remove(APACHE_DIR)
	except FileNotFoundError:
		pass

shutil.copytree(WORK_DIR, APACHE_DIR)
print("Configurations successfully deployed!")
backup = BACKUP_DIR + "/config.yaml." + TIMESTAMP
shutil.copy(CONFIG, backup)
print("Configurations successfully stored for backup as [%s]!" % (backup))
sys.exit(0)
