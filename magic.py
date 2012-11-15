#!/usr/bin/env python
import argparse, sys, string, time, re, os
import urllib, zipfile, subprocess

VERSION = 0.1
regReboot = False
verbose = False
# Todo: add system file checking against hashes, check process list against default, check program files, download all hashes from the internet
# 	convert to standalone executable when finished

try:
    from _winreg import *
except:
    pass
    #print 'magic is not currently running on a Windows system, aborting.'
    #exit()

class silentArgParse(argparse.ArgumentParser):
	def error(self, m):
		self.print_help()
		exit()

parser = silentArgParse(description='Automates common Windows security fixes. magic was written by the TJCSCC', prog='magic')
parser.add_argument('-q', help='perform all recommended fixes [put equivalent files]', action='store_true')
parser.add_argument('-t', metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable the telnet server')
parser.add_argument('-f', metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable the windows firewall')
parser.add_argument('-dl', metavar='tool', type=str, nargs='*', help='download latest versions of security tools')
parser.add_argument('-a', metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable adminshares')
parser.add_argument('-g', metavar='gpo script', type=str, nargs=1, help='modify group policy')
parser.add_argument('-p', metavar='port', type=str, nargs='+', help='open or close a firewall port. This does not enable the firewall if it is not started')
parser.add_argument('-n', metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable null sessions')
parser.add_argument('-vp', metavar='port', type=str, nargs='+', help='output information about system ports')
parser.add_argument('-fs', metavar='on/off', choices=['on', 'off'], type=str, nargs=1, help='enable or disable FTP/SMTP')
parser.add_argument('-i',  metavar='file', type=str, nargs='*', help='install windows patches')
parser.add_argument('-r', help='reboots the system', action='store_true')
parser.add_argument('-V', action='store_true', help='prints version information')
parser.add_argument('-v', action='store_true', help='show verbose output')
args= parser.parse_args()

#check for no arguments, and if there are none, print help
#later this might be changed to do some default operations
from sys import argv
if len(argv)<2:
	parser.print_help()

if args.V: # Print version info
    print "magic.py: version %s | Written by Cyrus Malekpour" % (str(VERSION))
    pass
    
if args.v: # [Flag] Show verbose output
    verbose = True
    pass

if args.q: # Perform all recommended fixes
    # FIXME
    pass

if args.t: # Telnet
    telnet(1 if 'on' in args.t else 0)

if args.f: # Firewall
    firewall(1 if 'on' in args.f else 0)

if args.dl: # Download tools
    # FIXME
    # Windows 8 has Defender, shouldn't need an antivirus
    # MSE runs on XP SP3, Vista, and 7
    pass

if args.a: # Adminshares
    adminshares()

if args.g: # Group Policy
    # FIXME
    pass

if args.p: # Firewall ports
    closeport(int(args.t[0]))
    pass

if args.n: # Null sessions
    nullsessions()
    pass

if args.vp: # Output system port info
    pass

if args.fs: # FTP/SMTP
    pass

if args.i: # Install patches
    pass

if args.r or regReboot == True: # Reboot the system
    reboot()

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
  SetValueEx(key, "restrictanonymous", 0, REG_DWORD, 2)
  CloseKey(key)

def reboot():
  print('Now restarting the system...')
  os.system('shutdown /r /f /t 000')

def downloadMaterial():
    # FIXME Download latest, individual tools. only install if flag is given
    print('Downloading and extr...')
    urllib.urlretrieve("http://db.tt/TZnIqw0p", "Tools.zip")
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

def disableFTPandSMTP():
  print('Disabling FTP and SMTP...')
  os.system('sysocmgr /i:%windir%\inf\sysoc.inf /u:'+os.getcwd()+'\comp.inf /r /q')
  os.remove(os.getcwd()+'\comp.inf')

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

#stopTelnet()
#enableFireWall()
#deleteAdminShares()
#downloadMaterial()
