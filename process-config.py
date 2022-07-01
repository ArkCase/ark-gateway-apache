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
#import shutil
#import stat
import sys
#import tempfile
#import time
#import traceback

TYPE_LIST = type([])
TYPE_STRING = type("")
TYPE_DICT = type({})

TRUE_VALUES = { "true" : True, "yes" : True, "y" : True, "1" : True, "on" : True, "enabled" : True, "enable" : True }

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

def processSsl(ssl):
	pass

def processModules(modules):
	pass

def processSites(sites):
	pass

def processConfs(confs):
	pass

try:
	ssl = yamlData["ssl"]
	try:
		processSsl(ssl)
	except Exception as e:
		fail("Failed to process the SSL configurations from [%s]: %s" % (CONFIG, str(e)))
except KeyError:
	print("No SSL configurations found in [%s]" % (CONFIG))

try:
	modules = yamlData["modules"]
	try:
		processModules(modules)
	except Exception as e:
		fail("Failed to process the module configurations from [%s]: %s" % (CONFIG, str(e)))
except KeyError:
	print("No module configurations found in [%s]" % (CONFIG))

try:
	sites = yamlData["sites"]
	try:
		processSites(sites)
	except Exception as e:
		fail("Failed to process the site configurations from [%s]: %s" % (CONFIG, str(e)))
except KeyError:
	print("No site configurations found in [%s]" % (CONFIG))

try:
	confs = yamlData["confs"]
	try:
		processConfs(confs)
	except Exception as e:
		fail("Failed to process the additional configurations from [%s]: %s" % (CONFIG, str(e)))
except KeyError:
	print("No additional configurations found in [%s]" % (CONFIG))

print("Configuration modifications applied per [%s]" % (CONFIG))
sys.exit(0)

