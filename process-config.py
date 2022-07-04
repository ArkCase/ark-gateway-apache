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

def processSsl(general, section):
	print("Processing the SSL section from: %s" % (section))

def processModules(general, section):
	print("Processing the module section from: %s" % (section))

def processSites(general, section):
	print("Processing the site section from: %s" % (section))

def processConfs(general, section):
	print("Processing the additional configuration section from: %s" % (section))

sections = []
sections += [( "ssl",     "SSL",        processSsl     )]
sections += [( "modules", "modules",    processModules )]
sections += [( "sites",   "sites",      processSites   )]
sections += [( "confs",   "additional", processConfs   )]

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
