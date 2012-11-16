#!/usr/bin/env python
import argparse
import logging
import os
import platform
import re
import string
import subprocess
import sys
import time
import urllib
import zipfile

VERSION = 0.1
regReboot = False

try:
    from _winreg import *
except:
    pass
    #print 'magic is not currently running on a Windows system, aborting.'
    #exit()


# START FUNCTIONS =============================================================

def resetdns():
    os.system("ipconfig /release")
    os.system("ipconfig /renew")
    os.system("ipconfig /flushdns")

def rdp(status):
    if status:
        os.system("reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f")
    else:
        os.system("reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f")

def ra(status):
    if status:
        os.system("reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_DWORD /d 1 /f")
    else:
        os.system("reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_DWORD /d 0 /f")

def telnet(status):
    if status:
        print('Starting the Telnet Service...')
        os.system("net start telnet")
        os.system("net start tlntsvr")
    else:
        print('Stopping the Telnet Service...')
        os.system("net stop telnet")
        os.system("net stop tlntsvr")

def firewall(status):
    version = platform.version()
    if float(version[:version.index('.', 2)]) >= 6:
        if status:
            print('Enabling the Firewall...')
            os.system('netsh advfirewall set currentprofile state on')
            os.system('netsh advfirewall set rule name=all profile=any new enable=no')
            os.system('netsh advfirewall set rule group="remote desktop" profile=any new enable=yes')
            os.system('netsh advfirewall set rule group="remote administration" profile=any new enable=yes')
        else:
            print('Disabling the Firewall...')
            os.system('netsh advfirewall set currentprofile state off')
    else:
        if status:
            print('Enabling the Firewall...')
            os.system('netsh firewall set opmode enable')
            os.system('netsh firewall set service all disable all')
            os.system('netsh firewall set service REMOTEDESKTOP enable all')
            os.system('netsh firewall set service REMOTEADMIN enable all')
        else:
            print('Disabling the Firewall...')
            os.system('netsh firewall set opmode disable')

def adminshares():
    print('Deleting admisistrative shares...')
    os.system('net share ADMIN$ /DELETE')
    os.system('net share print$ /DELETE')
    os.system('net share C$ /DELETE')
    os.system('net share D$ /DELETE')
    # FIXME save settings after reboot

def checkshell():
    if str(cmdCall("echo %COMSPEC%")) == 'C:\\Windows\\system32\\cmd.exe':
        return True
    return False

def closeport(port):
  print('Closing down port #' + port + '...')
  os.system('netsh firewall delete portopening ALL %d' % port)

def nullsessions():
  print('Disabling null sessions from the registry...')
  keyVal = r'System\CurrentControlSet\Control\Lsa'
  try:
    key = OpenKey(HKEY_LOCAL_MACHINE, keyVal, 0, KEY_ALL_ACCESS)
  except:
    key = CreateKey(HKEY_LOCAL_MACHINE, keyVal)
  SetValueEx(key, "RestrictAnonymous", 0, REG_DWORD, 2)
  SetValueEx(key, "RestrictAnonymousSAM", 0, REG_DWORD, 1)
  CloseKey(key)

def reboot():
  print('Now restarting the system...')
  os.system('shutdown /r /f /t 000')

def download():
    # FIXME Download latest, individual tools. only install if flag is given
    print('Downloading and extracting installers...')
    urllib.urlretrieve("http://db.tt/niDVOfmr", "Tools.zip")
    z = zipfile.ZipFile("Tools.zip")
    z.extractall()

def groupPolicy():
  print('Applying group policy settings...')
  os.system("secedit /configure /db lol.sdb /cfg " + os.getcwd() + "CyberPatriot.inf")
  os.system("gpupdate /force")

def viewPortInfo():
  print('Dumping port information')
  os.system('netstat -ano |find /i "listening" > portInfo.txt')
  os.system('netstat -ano |find /i "established >> portInfo.txt"')

def patchInstaller(dirOfPatches):
  print('Reading patch files in...')

  patches,errors = {},0

  #Change to the given directory, and you better hope it's correct
  #why is this needed??
  os.chdir(dirOfPatches)

  # Get all the paths in the directories
  for patch in os.listdir(dirOfPatches):
    if patch.endswith(".exe"):
      patch_cmd = patch + " /quiet /norestart"
      patches[patch] = patch_cmd

  print('Found ' + str(len(patches.keys())) + ' patches...')

  for patch in patches.keys():
    output = os.system(str([patches[patch]]))
    patches[patch] = output
    if output == -1:
      if subprocess.check_output([patch + '-q /z ER']) == -1:
        errors += 1
        
  print('Done with ' + str(errors) + ' errors out of ' + str(len(patches.keys())) + ' patches.')

  if errors > 0:
    print('--Failed patches:')
    for patch in patches.keys():
      if patches[patch] == -1:
        print('----' + patch)

def isNetworkConnected():
    pingout = cmdCall('ping 8.8.8.8 -c 1 -q -W 3')
    if '100% packet loss' in pingout:
        return False
    hostout = cmdCall('ping google.com -c 1 -q -W 3')
    if '100% packet loss' in pingout:
        return False
    return True
    
def cmdCall(command):
    return unicode(os.popen(command).read())

# Beginning of arguments

class silentArgParse(argparse.ArgumentParser):
	#def error(self, m):
	#	self.print_help()
	#	exit()
	pass

# END FUNCTIONS ===============================================================

# START READ ARGS =============================================================

parser = silentArgParse(description='Automates common Windows security fixes. magic was written by the TJCSCC', prog='magic') #, prefix_chars='-/') # prefix_chars doesn't work, as far as I can tell
parser.add_argument('-d', '--default', 			help='perform all default recommended fixes [put equivalent files]', action='store_true')
parser.add_argument('-V', '--version', 			action='store_true', help='prints version information')
parser.add_argument('-v', '--verbose', 			action='store_true', help='show verbose output')
parser.add_argument('-q', '--quiet', 			help='quiet mode', action='store_true')

parser.add_argument('-t', '--telnet',			metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable the telnet server')
parser.add_argument('-f', '--firewall',			metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable the windows firewall')
parser.add_argument('-dl', '--download',		metavar='tool', type=str, nargs='*', help='download latest versions of security tools')
parser.add_argument('-a', '--adminshares',		metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable adminshares')
parser.add_argument('-g', '--group-policy',		metavar='gpo script', type=str, nargs=1, help='modify group policy')
parser.add_argument('-p', '--ports',			metavar='port', type=str, nargs='+', help='open or close firewall ports. This does not enable the firewall if it is not started')
parser.add_argument('-n', '--null-sessions', 	        metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable null sessions')
parser.add_argument('-vp', '--print-ports', 	        metavar='port', type=str, nargs='+', help='output information about system ports')
parser.add_argument('-fs', '--ftp-smtp',		metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable FTP/SMTP')
parser.add_argument('-ip', '--install-patches',         metavar='file', type=str, nargs='*', help='install windows patches')
parser.add_argument('-r', '--reboot',			help='reboots the system', action='store_true')
args= parser.parse_args()

print vars(args)
# Check for having no arguments, and if there are none, print help
# later this might be changed to do some default operations
if len(sys.argv)<2:
	parser.print_help()
	exit(0)

# END READ ARGS =================================================================

# START LOGGING SET UP ==========================================================

# set up logging to a main full file
logging.basicConfig(level=logging.DEBUG,
					format='%(asctime)s %(levelname)-8s %(message)s',
					datefmt='%m-%d %H:%M',
					filename='magic-'+time.strftime("%Y-%m-%d,%H:%M:%S")+'-full.log',
					filemode='w')

# define a Handler which writes INFO messages or higher to an output file
output = logging.FileHandler('magic-'+time.strftime("%Y-%m-%d,%H:%M:%S")+'-output.log')
output.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(levelname)-8s %(message)s')
# tell the handler to use this format
output.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(output)

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(levelname)-8s %(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

# READ THIS AND IMPLEMENT IT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#to log something:
#logging.debug('this will be logged')
#logging.critical('this will be very importantly logged')
#use different levels for different things:
#DEBUG - debug message
#INFO - info message
#WARNING - warn message
#ERROR - error message
#CRITICAL - critical message


# END LOGGING SET UP ==========================================================

# START PROCESS ARGS ==========================================================

# code options ===

# Perform all recommended fixes
if args.default:
    nullsessions()
    adminshares()
    telnet(0)
    firewall(0)
    resetdns()
    rdp(0)
    ra(0)
    download()

# Print version info
if args.version: 
    print "magic.py: version %s | Written by the TJCSCC" % (str(VERSION))
    exit()

# Shows verbose output
# Prints everything to stdout, stdoutlog, and fulllog
if args.verbose: 
	# FIXME
    pass

# Suppresses most output
# Prints errors to stdout and stdoutlog, and everything to fulllog
if args.quiet: 
    # FIXME
    pass

# Telnet
if args.telnet:
    telnet(1 if 'on' in args.t else 0)

# Firewall
if args.firewall: 
    firewall(1 if 'on' in args.f else 0)

# Download tools
if args.download: 
    # FIXME
    # Windows 8 has Defender, shouldn't need an antivirus
    # MSE runs on XP SP3, Vista, and 7
    pass

# Adminshares
if args.adminshares:
    adminshares()

# Group Policy
if args.group_policy: 
    # FIXME
    pass

# Firewall ports
if args.ports: 
    print args.ports.split(' ')
    closeport(int(args.t[0]))

# Null sessions
if args.null_sessions:
    nullsessions()

# Output system port info
if args.print_ports: 
	# FIXME
    pass

# Install patches
if args.install_patches: 
	# FIXME
    pass

# Reboot the system (always last)
if args.reboot or regReboot == True:
    reboot()

# END PROCESS ARGS ==========================================================
