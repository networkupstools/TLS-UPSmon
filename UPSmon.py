#!/usr/bin/python3 -u
# UPSmon Manage local and remote NUT installations
# Called by systemctl start nut-py-monitor.service
# Copyright (C) 2019-2021 Roger Price. GPL v3 or later at your choice.
'''UPSmon Manage local and remote NUT installations'''
Version='1.3'

# Version 1.1 changes:
# 2020-10-26 RP Added built-in timer 'start'
# 2020-11-01 RP Redefine fd_log after logrotate
# 2020-11-08 RP Default port is IANA ups/401
# 2020-11-09 RP Ensure email and wall send 7-bit ascii
# 2020-11-11 RP Added statuses LB1, LB2 and LB3
# 2020-11-11 RP Test for m = None in data_time
# 2020-11-27 RP OS ID improvement

# Version 1.2 changes:
# 2021-05-30 RP primary/secondary are permissable alternatives to master/slave
# 2021-05-30 RP Added status LS
# 2021-08-19 RP Debian 11 uses /usr/bin/python3 v3.9

# Version 1.3 changes:
# 2022-09-05 RP Use Debian 11 as primary examplle
# 2022-09-06 RP Removed characters : and @ from NAME

# We need some library stuff
import argparse, ast, datetime, getpass, inspect, logging, io, os, pathlib, pwd
import re, signal, shlex, smtplib, socket, ssl, string, subprocess, sys, syslog, time
from threading import Timer
#from pyasn1_modules import pem, rfc2459
#from pyasn1.codec.der import decoder
try :
  from ply import lex, yacc
except ImportError as err :
  msg = ('Error 200: Unable to import lex and yacc from ply.\n'\
         '\t Reason: {}\n'\
         '\t This program uses PLY (Python Lex-Yacc).\n'\
         '\t Please install PLY.  It may be available to you as a package.\n'\
         '\t Use command "python3 -m pip install ply"\n'\
         '\t or you can download it from http://www.dabeaz.com/ply/ and\n'\
         '\t then install lex.py and yacc.py with your other Python modules.')\
         .format(err.args)
  print(msg, file=sys.stderr, flush=True)
  exit(1)
if   sys.version_info[0] >= 4 : pass
elif sys.version_info[0] == 3 and sys.version_info[1] >= 6 : pass
else :
  msg = ('Message 210: This program requires Python version 3.6 or later.\n'\
         '\t You are using version {}.')\
         .format(sys.version.replace('\n',' '))
  print(msg, file=sys.stderr, flush=True)
  exit(1)

#############################################################################################
# Functions Functions Functions Functions Functions Functions Functions Functions Functions #
#############################################################################################
# Function isempty returns True if a string, list or dictionary is empty. None = empty.
# Makes use of Python wierdness.
def isempty (enumerable) :
  if enumerable : return False
  else :          return True
def isnotempty (enumerable) :
  if enumerable : return True
  else :          return False
def boolean (b) :
  if b : return True
  else : return False

#############################################################################################
# Function printer calls print to send string to stdout
# If stdout has been disconnected, do nothing
def printer (line) :
  if stderr_redirect : return 0
  print(line)

#############################################################################################
# Function eprinter calls print to send string to stderr
# If stderr has been disconnected, do nothing
def eprinter (line) :
  if stderr_redirect : return 0
  print(line, file=sys.stderr, flush=True)

#############################################################################################
#############################################################################################
# Try to find an identifier for the Linux OS
# Returns opensuse, fedora, debian, ... or None
# See http://0pointer.de/blog/projects/os-release for background
def get_OS_id () :
  stdout_list, stderr_list = do_command(['uname', '-a'])  # -a needed for synology
  if stdout_list == None : return None    # uname failed
  if stderr_list == None : return None
  if stderr_list != [] : return None
  line = stdout_list[0].lower()
  if re.match(r'(?i).*aix.*',  line)        : return 'aix'
  if re.match(r'(?i).*darwin.*',  line)     : return 'darwin'
  if re.match(r'(?i).*freebsd.*', line)     : return 'freebsd'
  if re.match(r'(?i).*hp-ux.*',  line)      : return 'hpux'
  if re.match(r'(?i).*ipfire.*',  line)     : return 'ipfire'
  if re.match(r'(?i).*mac.*',  line)        : return 'mac'
  if re.match(r'(?i).*netbsd.*',  line)     : return 'netbsd'
  if re.match(r'(?i).*openbsd.*', line)     : return 'openbsd'
  if re.match(r'(?i).*openindiana.*', line) : return 'openindiana'
  if re.match(r'(?i).*synology.*',  line)   : return 'synology'
  if re.match(r'(?i).*linux.*', line) :
    try :
      with open('/etc/os-release', 'r') as fd :
        lines = fd.readlines()            # A list of lines, each ending with \n
        for line in lines :
          m = re.match(r'ID=(.*)$', line)
          if m : return m.group(1).lower() # E.g. debian
        return None                       # No ID in os-release
    except Exception :
      try :
        with open('/etc/gentoo-release', 'r') as fd :
          return 'gentoo'
      except Exception : return None      # No *-release
  msg = ('Error 620: get_OS_id error: I do not recognize uname result {}\n'\
         '\t Continuing ...').format(stdout_list[0])
  eprinter(msg) ; logger(msg)
  return None                             # Unknown uname

# Try to find out which non-root user runs the upsd daemon, and
# where the NUT configuration files are placed.
# Returns (user, directory)
def get_NUT_install_params () :
  OS_id = get_OS_id()                     # E.g. debian or None
  try :
    ud = {'aix':         ('nut',   '/etc/nut/'), # IBM AIX
          'amzn':        ('nut',   '/etc/ups/'), # Amazon Linux
          'arch':        ('nut',   '/etc/nut/'),
          'centos':      ('nut',   '/etc/ups/'),
          'darwin':      ('nut',   '/etc/nut/'),
          'debian':      ('nut',   '/etc/nut/'),
          'fedora':      ('nut',   '/etc/ups/'), # Includes Scientific Linux
          'freebsd':     ('uucp',  '/usr/local/etc/nut/'), # Includes FreeNAS
          'gentoo':      ('nut',   '/etc/nut/'),
          'hpux':        ('nut',   '/etc/nut/'), # HP-UX ? ?
          'ipfire':      ('nutmon','/etc/nut/'), # IPFire
          'kali':        ('nut',   '/etc/nut/'), # Similar to Debian
          'linuxmint':   ('nut',   '/etc/nut/'), # Close to Ubuntu
          'mac':         ('nut',   '/etc/nut/'),
          'mageia':      ('nut',   '/etc/nut/'), # Similar to Fedora
          'manjaro':     ('nut',   '/etc/nut/'),
          'netbsd':      ('nut',   '/etc/nut/'),
          'ol':          ('nut',   '/etc/ups/'), # Oracle Linux
          'openbsd':     ('ups',   '/etc/nut/'),
          'openindiana': ('nut',   '/etc/nut/'),
          'opensuse':    ('upsd',  '/etc/ups/'),
          'raspbian':    ('nut',   '/etc/nut/'),
          'rhel':        ('nut',   '/etc/ups/'),
          'slackware':   ('nut',   '/etc/nut/'),
          'sles':        ('upsd',  '/etc/ups/'), # SuSE Enterprise Linux
          'sles_sap':    ('upsd',  '/etc/ups/'), # SuSE Enterprise Linux
          'synology':    ('root',  '/usr/syno/etc/ups/'),
          'ubuntu':      ('nut',   '/etc/nut/'),
          None:          ('nut',   '/etc/nut/')}[OS_id]
    return ud
  except Exception : return ('nut', '/etc/nut/')  # Most likely configuration

#############################################################################################
# Function ensure_fqups(raw_ups)  Given a string which might or might not include
#                                 the group, domain and port, return a string with
#                                 group:name@domain:port completed.
# Intended for use in function read_conf which maintains variable current_group internally
def ensure_fqups (raw_ups) :
  host = group_host[current_group]  # Save some typing
  port = str(group_port[current_group])  # Save some typing
  DDlogger(('{}\n'\
            +tab+'ensure_fqups ({}) ... type(raw_ups)={}')\
            .format(fnl(), raw_ups, type(raw_ups)))
  if current_group == None :
    msg=("{} Error 220: ensure_fqups ({}):  internal error.\n"\
         +tab+"Variable current_group has not been defined\n"\
         +tab+"Exiting ...").format(blob, raw_ups)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)            # This causes exceptions in PLY

  m = re.split("@", raw_ups)      # Extract group:name and domain:port
  if len(m) == 1 :                # We have group:name, domain:port is implied
    ml = re.split(":", m[0])
    if len(ml) == 1 :             # We have name
      fq = current_group+':'+ml[0]+'@'+host+':'+port  # LOCAL:name@localhost:3493
    else :
      # Check that ml[0] is the current group
      if ml[0] == current_group : pass
      else :
        msg = ('{} Warning 221: UPS naming inconsistency\n'\
              +tab+'Declared name is {} but the currrent group is {}\n'\
              +tab+'Continuing ...').format(blob, raw_ups, current_group)
        eprinter(msg); logger(msg)
      fq = ml[0]+ml[1]+'@'+host+':'+port     # group:name@localhost:3493
  else :                          # We have x@y, look at x and y in m[0] and m[1]
    ml = re.split(":", m[0])
    if len(ml) == 1 :             # We have name
      fql = current_group+':'+ml[0] # Prefix the group
    else :
      # Check that ml[0] is the current group
      if ml[0] == current_group : pass
      else :
        msg = ('{} Warning 222: UPS naming inconsistency\n'\
              +tab+'Declared name is {} but the currrent group is {}\n'\
              +tab+'Continuing ...').format(blob, raw_ups, current_group)
        eprinter(msg); logger(msg)
      fql = ml[0]+ml[1]           # group:name
    mr = re.split(":", m[1])
    if len(mr) == 1 :             # We have domain
      # Check that mr[0] is the group's host
      if mr[0] == host : pass
      else :
        msg = ('{} Warning 223: UPS naming inconsistency\n'\
              +tab+'Declared name is {} but the currrent host is {}\n'\
              +tab+'Continuing ...').format(blob, raw_ups, host)
        eprinter(msg); logger(msg)
      fqr = mr[0]+port            # domain:3493
    else :
      # Check that mr[0] is the current group's host
      if mr[0] == host : pass
      else :
        msg = ('{} Warning 224: UPS naming inconsistency\n'\
              +tab+'Declared name is {} but the currrent host is {}\n'\
              +tab+'Continuing ...').format(blob, raw_ups, host)
        eprinter(msg); logger(msg)
      # Check that mr[1] is the current group's port
      if mr[1] == port : pass
      else :
        msg = ('{} Warning 225: UPS naming inconsistency\n'\
              +tab+'Declared name is {} but the currrent port is {}\n'\
              +tab+'Continuing ...').format(blob, raw_ups, port)
        eprinter(msg); logger(msg)
      fqr = mr[0]+mr[1]           # domain:port
    fq = fql+fqr                  # group:name@domain:port
  DDlogger(('{}\n'\
           +tab+'ensure_fqups ({}) => {}')\
           .format(fnl(), raw_ups, fq))
  return fq

#############################################################################################
# Function pp_ups simplifies the display of a fully qualified UPS if the name is of
#                       form LOCAL:UPS@localhost:3493
def pp_ups (fqups) :
  m = re.split("@|:", fqups)      # [group, ups, domain, port]
  if len(m) == 4 :
    if m[0] == 'LOCAL' :     g = ''
    else :                   g = m[0]+':'
    if m[2] == 'localhost' : d = ''
    else :                   d = '@'+m[0]
    if m[3] == '3493' :      dp = d+''
    else :                   dp = '@'+m[2]+':'+m[3]
    return g+m[1]+dp
  else :
    msg=("{} Error 230: pp_ups internal error.\n"\
        +tab+"Unable to parse {}\n"\
        +tab+"Exiting ...").format(blob, fqups)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

#############################################################################################
# Pretty print a socket object.  Returns a string.
# Socket may be class socket.socket or ssl.SSLSocket
def pp_sock (s, long=False) :
  try :              fd = s.fileno()      # User gives us a non-exitant socket
  except Exception : fd = -1
  if s.__class__==ssl.SSLSocket :
    lb = lob+lsb; rb = rsb+rob
  else :
    lb = lsb; rb = rsb
  if long == True :
    try :              IP, port = s.getsockname()      # ('127.0.0.1', 401)
    except Exception : IP, port = (None, None)
    try :              peer_IP, peer_port = s.getpeername()  # ('127.0.0.1', 38700)
    except Exception : peer_IP=None; peer_port = None
    try :              blocking = s.getblocking()      # True
    except Exception : blocking = None
    try :              timeout = s.gettimeout()        # 3.0
    except Exception : timeout = None
#    pp = 'fd={} {}:{}->{}:{} bl={} to={}'\
#         .format(fd, IP, port, peer_IP, peer_port, blocking, timeout)
    pp = 'fd={} {}:{}->{}:{}'\
         .format(fd, IP, port, peer_IP, peer_port)
  else :
    pp = 'fd={}'.format(fd)
  return lb + pp + rb

# Pretty print a string or byte code message.
# max is maximum size of displayd message
# Returns a string. with no trailing newlines
def pp_msg (msg, max=60) :
  if isinstance(msg, str) : smsg = msg
  else : smsg  = msg.decode('utf-8')
  s = no_trailing_newlines(smsg)
  ellipsis = '...'
  u = max - len(ellipsis)
  if len(s) > max :
    first = s[:u//2]                      # Use integers for indexing
    last = s[-u//2:]
    return first + ellipsis + last
  else : return s

#############################################################################################
# Read certificate and return as a pretty printed string.
# https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
# from pyasn1_modules import pem, rfc2459
# from pyasn1.codec.der import decoder
def pp_PEM (file, long=False) :
  regexp = r'^\s*[0-9a-f][0-9a-f]:'
  try :
    cert_txt = subprocess.check_output(["openssl", "x509", "-text", "-noout", "-in", file])
    pp_full = cert_txt.decode('utf-8')    # Result is a string
    if long : return pp_full              # Customer sees everything
    else :                                # Only the first line of the octets gets presented
      pp = []; first_octet_line = True
      for l in pp_full.split('\n') :
        if re.match(regexp,l) :           # True if octet line
          if first_octet_line : pp.append(l+' ...') ; first_octet_line = False
          else : first_octet_line = False
        else : pp.append(l) ; first_octet_line = True
      return '\n'.join(pp)
  except Exception as ex :
    msg = ('{} Error 240: pp_PEM unable to pretty print {}\n'\
           +tab+'Reason: {}')\
           .format(blob, file, ex)
    logger(msg); eprinter(msg)
    return None

#############################################################################################
# pp_timer returns a pretty printed threading.Timer
def pp_timer (t) :
  return '<Timer {} {}s {}>'.format(t.args[0], t.interval, t.name)

def pp_active_timers (dict) :
  return [pp_timer(dict[n]) for n in dict]

def pp_timer_list (list) :
  if len(list) == 0 : return '[]'
  elif len(list) == 1 : return '['+pp_timer(list[0])+']'
  else :
    timer_list = [pp_timer(t) for t in list]
    return '[' + ', '.join(timer_list) + ']'

#############################################################################################
# Function fnl () returns a string with a list of file names and line
# numbers of the point in the main program where it was called.
def fnl () :
  line_nums = []
  # https://docs.python.org/3/library/inspect.html
  current_frame = inspect.currentframe()
  all_frames = inspect.getouterframes(current_frame)
  for f in all_frames[1:] :
    dir_file_name, lineno = f[1], f[2]
    file_name = re.split('/',dir_file_name)[-1]     # Remove directory.  Not used
    line_nums.append('{}'.format(lineno))
    del f                                           # GC needs help with frames
  del current_frame, all_frames                     # more help for GC
  nums = line_nums[1:][::-1]                        # Avoid tracing fnl, reverse list
  return prog_name + '[' + DownArrow.join(nums) + ']'

# Function fnl () returns a string with the file name and line
# number of the point in the main program where it was called.
def fnl_short () :
  # https://docs.python.org/3/library/inspect.html
  current_frame = inspect.currentframe()
  all_frames = inspect.getouterframes(current_frame)
  top_frame = all_frames[-1]
  dir_file_name, lineno = top_frame[1], top_frame[2]
  del current_frame, all_frames, top_frame          # GC needs help with frames
  file_name = re.split('/',dir_file_name)[-1]       # Remove directory
  return '{}[{}]'.format(file_name, lineno)

#############################################################################################
# See https://stackoverflow.com/questions/2150739/iso-time-iso-8601-in-python
# date_time_µsec Local time in ISO format       2019-09-09 17:35:53.968428
# Experience shows that one must test m.  I don't know what causes this.
# Pythonism: m True means non-empty
def date_time_µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{} {}.{}'.format(m.group(1), m.group(2), m.group(3))
  else : return '{} {}.{}'.format(None, None, None)

# date_time      Local date and time in ISO format 2019-09-09 17:35:53
def date_time () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\..*',datetime.datetime.now().isoformat())
  if m : return '{} {}'.format(m.group(1), m.group(2))
  else : return '{} {}'.format(None, None)

# date           Local day in ISO format           2019-09-09
def date () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\..*',datetime.datetime.now().isoformat())
  if m : return '{}'.format(m.group(1))
  else : return '{}'.format(None)

# tod            Local time in ISO format          17:35:53
def tod () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\..*',datetime.datetime.now().isoformat())
  if m : return '{}'.format(m.group(2))
  else : return '{}'.format(None)

# System time including microseconds               2019-09-09.968428
def time_µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{}.{}'.format(m.group(2), m.group(3))
  else : return '{}.{}'.format(None, None)

# System time in microseconds                      968428
def µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{}'.format(m.group(3))
  else : return '{}'.format(None)

#############################################################################################
# Function open_log_file opens a file for logging
# The file owner will be uid, with group gid, e.g. upsd:daemon
# returns tuple (log, log_inode)   where
# log_file  is the name of the file, e,g, /var/log/NUT.log
# log       is a Python class providing log.write(...)
# log_inode is the inode of the log file
def open_log_file (log_file, uid, gid) :
  global log_file_open                    # pylint: disable=global-statement
  try :
    log = open(log_file, 'a')             # Opened for current user, re-open if user change
    log_file_open = True
    os.chmod(log_file, 0o664)
    os.chown(log_file, uid, gid)
    return (log, os.stat(log_file).st_ino)   # File class and inode number
  except FileNotFoundError :
    eprinter(('{} Error 250: I cannot find log file {}\n'\
             +tab+'Exiting ...').format(blob,log_file))
    cleanup(); exit(3)
  except PermissionError :
    eprinter(('{} Error 260: I cannot open log file {}, permissions error.\n'\
             +tab+'Exiting ...').format(blob,log_file))
    cleanup(); exit(3)

#############################################################################################
# Utility function logger appends line l to the log file
# provided that the current debug level is greater than or equal
# to d.  If d is omitted everything is logged.
# Function logger behaves like function print and automatically adds a \n
# at the end of the line.
# Log file log is kept permanently open in append mode.
# Messages are instantly flushed so log is safely written to disk
# even if we use kill to stop the daemon.
def logger (l, d=0) :
  global log, log_inode                   # pylint: disable=global-statement
  if isinstance(d, int) : pass
  else:
    msg = ('{} Error 270: Internal error\n'\
           +tab+'Type error in call to function logger("{}",{})\n'\
           +tab+'type({}) = {}\n'\
           +tab+'This may be due to writing ",format" instead of ".format"\n'\
           +tab+'Exiting ...').format(blob, l, d, d, type(d))
    eprinter(msg); cleanup(); exit(1)

  # Is the log file available?
  if not log_file_open : return 0

  # Has logrotate changed the inode of the log file ?
  if os.stat(log_file).st_ino == log_inode : new_inode_flag = '' # Marker for new file handle
  else :
    log.close()                           # Old file handle dead
    # Reopen a file for logging as the user who will run the server
    log, log_inode = open_log_file(log_file, os.getuid(), os.getgid())   # Re-opened for current user
    new_inode_flag = 'New inode {}. '.format(os.stat(log_file).st_ino)

  # And now, the logging action
  if debug >= d :
    # Friendly prefix for messages to the log file
    msg = '{} {} {}\n'.format(tod(), fnl(), new_inode_flag+l)
    try :
      rc = log.write(msg)                 # Ensure data recorded on disk in case we use kill
      log.flush()                         # to stop the daemon.
    except Exception : rc = -1            # File may have been closed by unexpected exit
    return rc                             # Returns number of characters written
  else : return 0

# As logger but for Lex and Yacc
def ylogger (l, y=0) :
  global log, log_inode                   # pylint: disable=global-statement
  if debugYacc >= y :
    # Is the log file available?
    if not log_file_open : return 0

    # Has logrotate changed the inode of the log file ?
    if os.stat(log_file).st_ino == log_inode : pass
    else :
      log.close()                         # Old file handle dead
      log, log_inode = open_log_file(log_file, os.getuid(), os.getgid())   # Re-opened for current user

    # Friendly prefix for messages to the log file
    msg = '{} {} {}\n'.format(tod(), fnl(), l)
    try :
      rc = log.write(msg)                 # Ensure data recorded on disk in case we use kill
      log.flush()                         # to stop the daemon.
    except Exception : rc = -1            # File may have been closed by unexpected exit
    return rc  # Returns number of characters written
  else : return 0

def Dlogger (l, d=1) : logger(l,d)
def DDlogger (l, d=2) : logger(l,d)
def Ylogger (l, y=1) : ylogger(l,y)
def YYlogger (l, y=2) : ylogger(l,y)

#############################################################################################
# A dictionary indexed by the user's name for the event, giving the corresponding
# table and required value.  dict, key = events_decode_dict()[event]
# Add TRIM and TEST
def events_decode_dict () :
  return {\
  (None,'ALARM')    :('ALARMNone',  'ALARM'),    ('ALARM',None)    :('ALARMNone',  None),
  (None,'BOOST')    :('BOOSTNone',  'BOOST'),    ('BOOST',None)    :('BOOSTNone',  None),
  (None,'BYPASS')   :('BYPASSNone', 'BYPASS'),   ('BYPASS',None)   :('BYPASSNone', None),
  (None,'CAL')      :('CALNone',    'CAL'),      ('CAL',None)      :('CALNone',    None),
  (None,'CHRG')     :('CHRGNone',   'CHRG'),     ('CHRG',None)     :('CHRGNone',   None),
  (None,'DISCHRG')  :('DISCHRGNone','DISCHRG'),  ('DISCHRG',None)  :('DISCHRGNone',None),
  (None,'FSD')      :('FSDNone',    'FSD'),      ('FSD',None)      :('FSDNone',    None),
  (None,'LB')       :('LBNone',     'LB'),       ('LB',None)       :('LBNone',     None),
  (None,'LB1')      :('LB1one',     'LB1'),      ('LB1',None)      :('LB1None',    None),
  (None,'LB2')      :('LB2None',    'LB2'),      ('LB2',None)      :('LB2None',    None),
  (None,'LB3')      :('LB3None',    'LB3'),      ('LB3',None)      :('LB3None',    None),
  (None,'LS')       :('LSNone',     'LS'),       ('LS',None)       :('LSNone',     None),
  ('COMM','NOCOMM') :('COMMNOCOMM', 'NOCOMM'),   ('NOCOMM','COMM') :('COMMNOCOMM', 'COMM'),
  (None,'OFF')      :('OFFNone',    'OFF'),      ('OFF',None)      :('OFFNone',    None),
  ('OB','OL')       :('OLOB',       'OL'),       ('OL','OB')       :('OLOB',       'OB'),
  (None,'OVER')     :('OVERNone',   'OVER'),     ('OVER',None)     :('OVERNone',   None),
  (None,'RB')       :('RBNone',     'RB'),       ('RB',None)       :('RBNone',     None),
  (None,'TEST')     :('TESTNone',   'TEST'),     ('TEST',None)     :('TESTNone',   None),
  (None,'TICK')     :('TICKNone',   'TICK'),     ('TICK',None)     :('TICKNone',   None),
  (None,'TOCK')     :('TOCKNone',   'TOCK'),     ('TOCK',None)     :('TOCKNone',   None),
  (None,'TRIM')     :('TRIMNone',   'TRIM'),     ('TRIM',None)     :('TRIMNone',   None)}

# What actions are possible when an event occurs?
def action_keyword_dict () :
  return {'cancel_timer':cancel_timer,   'debug_level':set_debug,
          'email':emailer,               'email2':printer,
          'EPRINT':eprinter,             'NOTIFY':notifier,
          'NUTLOG':logger,               'PRINT':printer,
          'SETFSD':set_FSD,              'SHELLCMD':do_shellcmd,
          'SHUTDOWNCMD':do_shutdown,     'start_timer':start_timer,
          'SYSLOG':syslogger,            'WALL':waller}

# A list of all the UPS statuses known
def statuses () :
  candidates = [x[1] for x in events_decode_dict()]  # Allows duplicates
  return list(dict.fromkeys(candidates))  # The python way of removing duplicates

#############################################################################################
# Read configuration file. Returns 0 succeeds, 1 otherwise.
# Places result in global variables
def read_conf(conffile) :
  global current_ups, current_group, read_conf_rc # pylint: disable=global-statement
  confname = re.split(r'/',conffile)[-1]  # E.g. /here/there/ups-mgr.conf => ups-mgr.conf
  logger('Reading configuration file from {} ...'.format(confname))
  LN = 10000   # Pack lineno and col pos into single integer with this lineno multiplier
  current_group = None                    # GROUP declaration will provide value
  current_ups = None                      # MONITOR declaration will provide value

  # Useful regular expressions
  # Extract gr, name, domain and port from fqups such as HD:heartbeat@localhost:3493
  re_fqups = r'([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)'

  # Set up a PLY logging object
  logging.basicConfig(
    level = logging.DEBUG,
    filename = "UPSmon-PLY.log",
    filemode = "w",
    format = "%(filename)10s:%(lineno)4d:%(message)s"
   )
  PLYlog = logging.getLogger()

  # Helper functions simplify writing of lexer rules
  # DD_t assumes t.lineno is of form L*LN + C, L = line number, C = col number
  def DD_t (t) :
    YYlogger('{}[{},{}] {}'.format(confname,t.lineno//LN,t.lineno%LN, t))
  # Attribute lexer.linepos provides lexer position of first character in line
  def help (t) :     # Single parameter a
    ln = t.lineno*LN + (t.lexpos-t.lexer.linepos)
    va = lexer.lexmatch.group('a')        # Ensure result is always a string
    return (ln,va)
  def help2 (t) :    # Two parameters a and b
    ln = t.lineno*LN + (t.lexpos-t.lexer.linepos)
    va1 = lexer.lexmatch.group('a')       # Ensure result is always a string
    va2 = lexer.lexmatch.group('b')       # Ensure result is always a string
    return (ln,(va1,va2))
  # Combined line and column number
  def ln (t) : p = t.lineno*LN + (t.lexpos-t.lexer.linepos); return p

  # Lexer for the configuration file
  # List of token names.   This is always required
  tokens = ['WHEN', 'WALL', 'USER', 'UPSDUSER', 'TYPE', 'TO', 'TIMEOUT',
            'SYSLOG', 'SUBJECT', 'STATUS', 'STARTTIMER', 'SMTPSERVER',
            'SHUTDOWNCMD', 'SHELLCMD', 'SETFSD',
            'REPORTS', 'RARR', 'QUOTETEXT5', 'QUOTETEXT4',
            'QUOTETEXT3', 'QUOTETEXT2','QUOTETEXT1', 'PRINT', 'POWERVAL',
            'PORT', 'POLLFREQALERT', 'POLLFREQ', 'PASSWORD', 'NUTLOG',
            'NUMBER', 'NOTIFY', 'NAME', 'MONITOR',
            'MINSUPPLIES', 'MESSAGE', 'LET', 'IF',
            'HOST', 'GROUP', 'FROM', 'EQ', 'EPRINT', 'EMAIL', 'DEBUG',
            'COLON', 'CERTFILE', 'CANCELTIMER', 'APCUPSDUSER']

  ###########################################################################################
  # Token specifications
  # Token t has attributes t.type, t.value, t.lineno, and t.lexpos.
  # A string containing ignored characters (spaces and tabs)
  t_ignore  = ' \t'
  # Track the line numbers.  The column number are given by t.lexpos - t.lexer.linepos
  def t_newline (t) :
    r'\n'
    colpos = (t.lexpos - t.lexer.linepos)
    t.lexer.linepos = t.lexpos + 1        # Lexer position of first character in next line
    t.lexer.lineno += 1
  # Functions are matched in order of definition
  def t_ignore_COMMENT (t) :   r'\#[^\n]*' ;         t.lineno = ln (t)
  def t_WHEN (t) :             r'WHEN' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_WALL (t) :             r'WALL' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_USER (t) :             r'USER' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_UPSDUSER (t) :         r'UPSDUSER' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_TYPE (t) :             r'TYPE' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_TIMEOUT (t) :          r'TIMEOUT' ;          t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SYSLOG (t) :           r'SYSLOG' ;           t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SUBJECT (t) :          r'SUBJECT' ;          t.lineno = ln (t) ; DD_t (t) ; return t
  def t_STARTTIMER (t) :       r'STARTTIMER' ;       t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SMTPSERVER (t) :       r'SMTPSERVER' ;       t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SHUTDOWNCMD (t) :      r'SHUTDOWNCMD' ;      t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SHELLCMD (t) :         r'SHELLCMD' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_SETFSD (t) :           r'SETFSD' ;           t.lineno = ln (t) ; DD_t (t) ; return t
  def t_REPORTS (t) :          r'REPORTS' ;          t.lineno = ln (t) ; DD_t (t) ; return t
  def t_RARR (t) :             r'->' ;               t.lineno = ln (t) ; DD_t (t) ; return t
  def t_QUOTETEXT5 (t) :
    r'⸢(?P<a>[^⸥\r\n]*)⸥'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_QUOTETEXT4 (t) :
    r'⎡(?P<a>[^⎦\r\n]*)⎦'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_QUOTETEXT3 (t) :
    r'«(?P<a>[^»\r\n]*)»'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_QUOTETEXT2 (t) :
    r'"(?P<a>[^\"\r\n]*)"'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_QUOTETEXT1 (t) :
    r'\'(?P<a>[^\'\r\n]*)\''
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_PRINT (t) :            r'PRINT' ;            t.lineno = ln (t) ; DD_t (t) ; return t
  def t_POWERVAL (t) :         r'POWERVAL' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_PORT (t) :             r'PORT' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_POLLFREQALERT (t) :    r'POLLFREQALERT' ;    t.lineno = ln (t) ; DD_t (t) ; return t
  def t_POLLFREQ (t) :         r'POLLFREQ' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_PASSWORD (t) :         r'PASSWORD' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_NUTLOG (t) :           r'NUTLOG' ;           t.lineno = ln (t) ; DD_t (t) ; return t
  def t_NUMBER (t) :
    r'(?P<a>[0-9.]+)'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t
  def t_NOTIFY (t) :           r'NOTIFY';            t.lineno = ln (t) ; DD_t (t) ; return t
  def t_MONITOR (t) :          r'MONITOR';           t.lineno = ln (t) ; DD_t (t) ; return t
  def t_MINSUPPLIES (t) :      r'MINSUPPLIES';       t.lineno = ln (t) ; DD_t (t) ; return t
  def t_MESSAGE (t) :          r'MESSAGE' ;          t.lineno = ln (t) ; DD_t (t) ; return t
  def t_LET (t) :              r'LET' ;              t.lineno = ln (t) ; DD_t (t) ; return t
  def t_IF (t) :               r'IF' ;               t.lineno = ln (t) ; DD_t (t) ; return t
  def t_HOST (t) :             r'HOST' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_GROUP (t) :            r'GROUP' ;            t.lineno = ln (t) ; DD_t (t) ; return t
  def t_FROM (t) :             r'FROM' ;             t.lineno = ln (t) ; DD_t (t) ; return t
  def t_EQ (t) :               r'=' ;                t.lineno = ln (t) ; DD_t (t) ; return t
  def t_EPRINT (t) :           r'EPRINT' ;           t.lineno = ln (t) ; DD_t (t) ; return t
  def t_EMAIL (t) :            r'EMAIL' ;            t.lineno = ln (t) ; DD_t (t) ; return t
  def t_DEBUG (t) :            r'DEBUG' ;            t.lineno = ln (t) ; DD_t (t) ; return t
  def t_COLON (t) :            r'\:' ;               t.lineno = ln (t) ; DD_t (t) ; return t
  def t_CERTFILE (t) :         r'CERTFILE' ;         t.lineno = ln (t) ; DD_t (t) ; return t
  def t_CANCELTIMER (t) :      r'CANCELTIMER' ;      t.lineno = ln (t) ; DD_t (t) ; return t
  def t_APCUPSDUSER (t) :      r'APCUPSDUSER' ;      t.lineno = ln (t) ; DD_t (t) ; return t
  # The following tokens are placed low in the list so that keywords will be detected
  # as such and not seen as just names.
  def t_STATUS (t) :           # Created with sorted(list(dict.fromkeys([x[0] for x in D])))
    r'None|ALARM|BOOST|BYPASS|CAL|CHRG|NOCOMM|DISCHRG|FSD|LB1|LB2|LB3|LB|LS|COMM|OB|OFF|OL|OVER|RB|TEST|TICK|TOCK|TRIM'
    if t.value == 'None' : t.value = None
    t.lineno = ln (t) ; DD_t (t) ; return t
  def t_TO (t) :               r'TO' ;               t.lineno = ln (t) ; DD_t (t) ; return t
  def t_NAME (t) :                        # Names for humans, groups, timers, UPS's, messages
    # r'(?P<a>[a-zA-Z_][a-zA-Z0-9._%+-:@]*)'   Removed : and @
    r'(?P<a>[a-zA-Z_][a-zA-Z0-9._%+-]*)'
    t.lineno, t.value = help (t) ; DD_t (t) ; return t

  # Error handling rule
  def t_error(t):
    global read_conf_rc                   # pylint: disable=global-statement
    colpos = (t.lexpos - t.lexer.linepos)
    msg = "{}[{},{}] Error 280: I have no way of parsing this character: {}"\
          .format(confname, t.lineno, colpos, t.value[0])
    eprinter(msg); logger(msg)
    t.lexer.skip(1)
    read_conf_rc = 1                      # This configuration not acceptable

  ###########################################################################################
  # Parse rules for the configuration file.
  # Constructs an abstract syntax tree to be interpreted later.
  def p_configuration (p) :
    'configuration : intros groups'
    global AST                            # pylint: disable=global-statement
    tag = ('configuration', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    AST = (tag, p[1], p[2])
    #YYlogger(('{}\n'\
    #         +tab+'p_configuration dir(p)=\n'\
    #         +tab+'{}')\
    #         .format(fnl(), dir(p)))

  def p_intros (p) :                      # Tuple of introductory declarations
    '''intros : intro
              | intros intro'''
    tag = ('intros', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, p[1])
    else           : p[0] = (p[1][:] + (p[2],))

  def p_intro (p) :                       # Returns e.g. [('intro', ('pollfreq', '5')), ('pollfreq', '5'))]
    '''intro : smtp
             | let
             | pollfreqalert
             | pollfreq'''
    tag = ('intro', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1])

  def p_smtp (p) :
    'smtp : SMTPSERVER quotetext PORT number USER quotetext PASSWORD quotetext'
    tag = ('smtp', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2], p[4], p[6], p[8])

  def p_let (p) :
    'let : LET name EQ quotetexts'
    tag = ('let', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2], p[4])

  def p_number (p) :
    'number : NUMBER'
    tag = ('number', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1])                    # Returns a string such as '10.5'

  def p_pollfreqalert (p) :
    'pollfreqalert : POLLFREQALERT number'
    tag = ('pollfreqalert', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_pollfreq (p) :
    'pollfreq : POLLFREQ number'
    tag = ('pollfreq', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_groups (p) :
    '''groups : group_element
              | groups group_element'''
    tag = ('groups', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, p[1])
    else           : p[0] = (p[1][:] + (p[2],))

  def p_group_element (p) :
    '''group_element : group_name
                     | group_host
                     | group_port
                     | certfile
                     | let
                     | monitors
                     | minsupplies
                     | action_declarations'''
    tag = ('group_element', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1])

  def p_group_name (p) :
    'group_name : GROUP name'
    tag = ('group_name', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_name (p) :
    'name : NAME'
    tag = ('name', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1])

  def p_group_host (p) :
    'group_host : HOST name'
    tag = ('group_host', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_group_port (p) :
    'group_port : PORT number'
    tag = ('group_port', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_certfile (p) :
    '''certfile : CERTFILE quotetext
                | CERTFILE name'''
    tag = ('certfile', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])
    YYlogger(('{}\n'\
              +tab+'p_certfile returns\n'\
              +tab+'==> p[0]={}').format(fnl(), p[0]))

  def p_monitors (p) :
    '''monitors : monitor
                | monitors monitor'''
    tag = ('monitors', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, p[1])
    else           : p[0] = (p[1][:] + (p[2],))

  def p_monitor (p) :
    'monitor : MONITOR name POWERVAL number user PASSWORD quotetext TYPE name'
    tag = ('monitor', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2], p[4], p[5][1], p[7], p[9])
    YYlogger(('{}\n'\
              +tab+'p_monitor returns\n'\
              +tab+'==> p[0]={}').format(fnl(), p[0]))

  def p_user (p) :
    '''user : UPSDUSER name
            | APCUPSDUSER name'''
    tag = ('user', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_minsupplies (p) :
    'minsupplies : MINSUPPLIES number'
    tag = ('minsupplies', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_action_declarations (p) :
    '''action_declarations : action_declaration
                           | action_declarations action_declaration'''
    tag = ('action_declarations', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, p[1])
    else           : p[0] = (p[1][:] + (p[2],))

  def p_action_declaration (p) :          # E.g. LOCAL:Eaton@localhost:3493(OL,OB) [(K,T), actions, ...]
    'action_declaration : event_key actions'
    tag = ('action_declaration', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1], p[2])              # p[1] is a tuple, p[2] is a list of strings
    YYlogger(('{}\n'\
             +tab+'p_action_declaration returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_event_key (p) :
    '''event_key : WHEN name TIMEOUT name               COLON
                 | WHEN name TO      name               COLON
                 | WHEN name REPORTS STATUS RARR STATUS COLON'''
    tag = ('event_key', p.lineno(2)//LN, p.lineno(2)%LN)
    if len(p) == 6 : p[0] = (tag, p[2], 'TO', p[4])
    else           : p[0] = (tag, p[2], p[4], p[6])
    YYlogger(('{}\n'\
             +tab+'p_event_key returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))
    YYlogger(('{}\n'\
             +tab+'p_event_key p.lineno(3)={} p.lexpos(3)={}')\
             .format(fnl(), p.lineno(3), p.lexpos(3)))

  def p_actions (p) :
    '''actions : action_element
               | actions action_element'''
    tag = ('actions', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, p[1])
    else           : p[0] = (p[1][:] + (p[2],))

  def p_action_element (p) :
  # Returns :
  # ('action_element',c,'start_timer','(\'HB-timer\',30)') where c is the condition
  # ('action_element',c,'SETFSD',('quotetexts', ('my-ups1, 'my-ups2',...)
  # ('action_element',c,'PRINT',('quotetexts', ('Hello',...))
    '''action_element : condition cancel_timer
                      | condition debug_level
                      | condition email
                      | condition start_timer
                      | condition EPRINT           quotetexts
                      | condition NOTIFY           quotetexts
                      | condition NUTLOG           quotetexts
                      | condition PRINT            quotetexts
                      | condition SETFSD           name
                      | condition SHELLCMD         quotetexts
                      | condition SHUTDOWNCMD      quotetexts
                      | condition SYSLOG           quotetexts
                      | condition WALL             quotetexts'''
    YYlogger(('{}\n'\
              +tab+'p_action_element receives... len(p[:])={} len(p[1])={}\n'\
              +tab+'==> p={}').format(fnl(), len(p[:]), len(p[1]), p[:]))
    tag = ('action_element', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    # Pick out the quotetexters
    if len(p) == 3 : condition = (p[1][1],p[1][2]) ; action_keyword = p[2][0][0] ; action_text = p[2][1]
    else :           condition = (p[1][1],p[1][2]) ; action_keyword = p[2]       ; action_text = p[3]
    p[0] = (tag, (condition, action_keyword, action_text))
    YYlogger(('{}\n'\
             +tab+'p_action_element returns\n'\
             +tab+'==> p[0]={}').format(fnl(), p[0]))

  def p_condition (p) :
    '''condition : IF STATUS RARR STATUS
                 | empty'''
    tag = ('condition', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 5 : p[0] = (tag, p[2], p[4])
    else           : p[0] = (tag, None, None)
    YYlogger(('{}\n'\
             +tab+'p_condition returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_quotetexts (p) :
    # Reads text strings "bla bla ..." ' more bla ...' ⸢... etcetera ...⸥
    # Returns single Python string in tuple ('quotetexts', ('bla bla ...', ' more bla ...', '... etcetera ...'))
    # MSGS substitution is done in funtion e
    '''quotetexts : quotetext
                  | name
                  | quotetexts quotetext
                  | quotetexts name'''
    tag = ('quotetexts', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    if len(p) == 2 : p[0] = (tag, (p[1][1],))
    else :           p[0] = (tag, p[1][1] + (p[2][1],))    # Tuple concatenation
    YYlogger(('{}\n'\
             +tab+'p_quotetexts returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_quotetext (p) :
    # MSGS substitution is done in funtion e
    '''quotetext : QUOTETEXT1
                 | QUOTETEXT2
                 | QUOTETEXT3
                 | QUOTETEXT4
                 | QUOTETEXT5'''
    tag = ('quotetext', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[1])
    YYlogger(('{}\n'\
             +tab+'p_quotetext returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_cancel_timer (p) :
    'cancel_timer : CANCELTIMER name'
    tag = ('cancel_timer', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  def p_debug_level (p) :
    'debug_level : DEBUG number'
    tag = ('debug_level', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])

  # Receives p[2] = 'HB-timer, p[3] = 20, returns e.g. ('start_timer',("HB-timer",30))
  def p_start_timer (p) :
    'start_timer : STARTTIMER name number'
    tag = ('start_timer', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, (p[2], p[3]))

  def p_email (p) :
    'email : EMAIL from to subject content'
    tag = ('email', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, (p[2][1], p[3][1], p[4][1], p[5][1]))
    YYlogger(('{}\n'\
             +tab+'p_email returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_from (p) :
    'from : FROM quotetext'
    tag = ('from', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])
    YYlogger(('{}\n'\
             +tab+'p_from returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_to (p) :
    'to : TO quotetext'
    tag = ('to', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])
    YYlogger(('{}\n'\
             +tab+'p_to returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_subject (p) :
    'subject : SUBJECT quotetext'
    tag = ('subject', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])
    YYlogger(('{}\n'\
             +tab+'p_subject returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_content (p) :
    'content : MESSAGE quotetexts'
    tag = ('content', p.lineno(len(p)-1)//LN, p.lineno(len(p)-1)%LN)
    p[0] = (tag, p[2])
    YYlogger(('{}\n'\
             +tab+'p_content returns\n'\
             +tab+'p[0]={}').format(fnl(), p[0]))

  def p_empty(p) :                        # The empty production
    'empty :'
    pass

  def p_error (t) :
    global read_conf_rc                   # pylint: disable=global-statement
    # Note: t is a LexToken
    # E.g. t.lexpos=377, t.lineno=130000, t.type=POLLFREQALERT, t.value= 5,
    #      t.lexer.lineno=13, t.lexer.lexpos=392,  t.lexer.linepos=377
    #print(('\n'\
    #      +tab+'p_error({}) called ... dir(t.lexer)=\n'\
    #      +tab+'{}\n'\
    #      +tab+'t.lexer.lineno={}, t.lexer.lexpos={},  t.glexer.linepos={},'\
    #      +tab+'t.lexpos={}, t.lineno={}, t.type={}, t.value={}')\
    #      .format(t, t.lexer, t.lexer.lineno, t.lexer.lexpos,  t.lexer.linepos,
    #              t.lexpos, t.lineno, t.type, t.value))
    read_conf_rc = 1                      # This configuration not acceptable
    if t == None :
      msg = '{} Message 290: This configuration file is incomplete or empty.  Nothing to do.'\
            .format(confname)
      logger(msg); eprinter(msg)
    else :
      msg = ('{}[{},{}] Error 300: Configuration file error\n'\
            +tab+'The parser does not understand token type {} value {} on line {}.\n'\
            +tab+'This configuration file will not be used.')\
            .format(confname, t.lineno//LN, t.lineno%LN, t.type, t.value, t.lineno//LN)
      logger(msg); eprinter(msg)

  ###########################################################################################
  # Interpret the syntax tree
  # Tree is of form ( (tag, row, col), payload )
  def e (AST) :
    global read_conf_rc                                 # pylint: disable=global-statement
    global SMTP_Server, SMTP_Port, SMTP_User, SMTP_Pass # pylint: disable=global-statement
    global pollfreqalert, pollfreq                      # pylint: disable=global-statement
    global grs, current_group, current_ups              # pylint: disable=global-statement
    def tag (ast) : return ast[0][0]
    YYlogger(("{}\n"\
             +tab+"e ({},...)").format(fnl(), AST[0]))
    adornment = {'u':'1', 'c':'2', 'e':'3', 'b':'4', 'h':'5'}      # Copied from do_action

    if   tag(AST) == 'configuration' : e (AST[1]) ; e (AST[2])

    elif tag(AST) == 'intros' :
      for i in AST[1:] : e (i)

    elif tag(AST) == 'intro' : e (AST[1])

    elif tag(AST) == 'let' :
      name = e (AST[1]); value = e (AST[2])
      msgs[name] = value                  # E.g. msgs['msg.1'] = "Hello"
      YYlogger(("{}\n"\
               +tab+"\te ({},...) Initialized msgs[{}] with {}")\
               .format(fnl(), AST[0], name, msgs[name]))
      # Pick off special case of battery.charge.low.i
      b_c_l_i = {'battery.charge.low.1':1, 'battery.charge.low.2':2, 'battery.charge.low.3':3}
      if name in b_c_l_i :
        try : int_value = int(value)      # Extract integer value from quotetext.  E.g. '50'
        except Exception :
          int_value = 0
          msg=('{}[{},{}] Error 307: {} value \'{}\' is not a quoted integer.')\
               .format(confname, AST[0][1], AST[0][2], name, value)
          logger(msg); eprinter(msg)
          read_conf_rc = 1                # This configuration not acceptable
        if current_ups == None :
          msg=('{}[{},{}] Error 305: {} declaration not in scope of MONITOR declaration.\n'\
               +tab+'Hint: Place this LET declaration after the corresponding MONITOR declaration.')\
               .format(confname, AST[0][1], AST[0][2], name)
          logger(msg); eprinter(msg)
          read_conf_rc = 1                # This configuration not acceptable
        else :
          i = b_c_l_i[name]               # 1, 2 or 3
          battery_charge_low[current_ups][i] = int_value
          msg=('{}[{},{}] Message 306: UPS {} setting {} to {}')\
              .format(confname, AST[0][1], AST[0][2], current_ups, name, int_value)
          logger(msg)

    elif tag(AST) == 'quotetexts' :
      first = True                        # Build up the text
      for q in AST[1] :
        try :              t = msgs[q]    # Resolve MESSAGE
        except Exception : t = q
        if first : text = t ; first = False
        else:      text = ''.join([text, t])   # pylint: disable=undefined-loop-variable
      # Are the % substitutions correct ?  This is just a test.  The real substitutions
      # happen in function do_action when some event occurs.
      try : ignore = text % adornment
      except ValueError as err :
        msg=('{}[{},{}] Error 310: Invalid use of a %(var)s expression\n'\
            +tab+'text = {}\n'\
            +tab+'Error: {}\n'\
            +tab+'Hint: Valid variables in % expressions are {}')\
            .format(confname, AST[0][1], AST[0][2], text, err.args, [v for v in adornment])
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      YYlogger(('{}\n'\
               +tab+'e ({},...)\n'\
               +tab+'returns {}')\
               .format(fnl(), AST[0], text))
      return text

    elif tag(AST) == 'quotetext' :
      try :              text = msgs[AST[1]] # Resolve MESSAGE
      except Exception : text = AST[1]
      # Are the % substitutions correct ?  This is just a test.  The real substitutions
      # happen in function do_action when some event occurs.
      try : ignore = text % adornment
      except ValueError as err :
        msg=('{}[{},{}] Error 320: Invalid use of a %(var)s expression\n'\
            +tab+'text = {}\n'\
            +tab+'Error: {}\n'\
            +tab+'Hint: Valid variables in % expressions are {}')\
            .format(confname, AST[0][1], AST[0][2], text, err.args, [v for v in adornment])
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      YYlogger(('{}\n'\
               +tab+'e ({},...)\n'\
               +tab+'returns {}')\
               .format(fnl(), AST[0], text))
      return text

    elif tag(AST) == 'name' :
      return AST[1]

    elif tag(AST) == 'number' :
      raw_number = AST[1]                 # E.g. string '5.5'
      try : number = float(raw_number)    # E.g. float 5.5
      except Exception :
        msg = '{}[{},{}] Error 330: {} is not an integer or floating point number.'\
              .format(confname, AST[0][1], AST[0][2], raw_number)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      return number

    elif tag(AST) == 'smtp' :
      ### Server ###
      SMTP_Server = e (AST[1])            # E.g. mail.example.com

      ### Port ###
      SMTP_Port = int(e (AST[2]))          # E.g. 465
      if SMTP_Port>0 and SMTP_Port<65536 : pass
      else :
        msg = '{}[{},{}] Error 340: PORT {} . Port number not in range 0..65535.'\
              .format(confname, AST[0][1], AST[0][2], SMTP_Port)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
        return 1

      ### User ###
      SMTP_User = e(AST[3])               # E.g. mailbox@example.com

      ### Password ###
      SMTP_Pass = e(AST[4])               # E.g. sekret

      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized SMTP_Server {}, SMTP_Port {}, SMTP_User {}, SMTP_Pass {}")\
               .format(fnl(), AST[0], SMTP_Server, SMTP_Port, SMTP_User, SMTP_Pass))

    elif tag(AST) == 'pollfreqalert' :
      pollfreqalert = e (AST[1])          # E.g. string '2.5'
      if pollfreqalert>0 : pass
      else :
        msg = '{}[{},{}] Error 360: POLLFREQALERT {} . Value is not a positive number.'\
              .format(confname, AST[0][1], AST[0][2], raw_pollfreqalert)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized POLLFREQALERT {}")\
               .format(fnl(), AST[0], pollfreqalert))

    elif tag(AST) == 'pollfreq' :
      pollfreq = e (AST[1])               # E.g. string '5.5'
      if pollfreq>0 : pass
      else :
        msg = '{}[{},{}] Error 370: POLLFREQ {} . Value is not a strictly positive number.'\
              .format(confname, AST[0][1], AST[0][2], pollfreq)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized POLLFREQ {}")\
               .format(fnl(), AST[0], pollfreq))

    elif tag(AST) == 'groups' :
      for i in AST[1:] : e (i)

    elif tag(AST) == 'group_element' :
      group_element = e (AST[1])
      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized group_element {}")\
               .format(fnl(), AST[0], group_element))

    elif tag(AST) == 'group_name' :
      group_name = e (AST[1])
      if group_name in grs :
        msg=("{}[{},{}] Error 400: GROUP {} already declared.\n"\
            +tab+"I am ignoring this declaration.")\
            .format(confname, AST[0][1], AST[0][2], group_name)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      else :
        current_group = group_name ; grs = grs + [current_group]
        group_host[current_group] = 'localhost'   # Default value
        group_port[current_group] = 3493          # Default value
        minsupplies[current_group] = 1    # Default value
        YYlogger(("{}\n"\
                 +tab+"e ({},...) Initialized GROUP {}\n"\
                 +tab+'Initialized default MINSUPPLIES {}\n'\
                 +tab+'Initialized default HOST {}\n'\
                 +tab+'Initialized default PORT {}')\
                 .format(fnl(), AST[0], current_group, minsupplies[current_group],
                         group_host[current_group], group_port[current_group]))

    elif tag(AST) == 'group_host' :
      group_host[current_group] = e (AST[1])
      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized HOST {}")\
               .format(fnl(), AST[0], group_host[current_group]))

    elif tag(AST) == 'group_port' :
      group_port[current_group] = int(e (AST[1]))
      YYlogger(("{}\n"\
               +tab+"e ({},...) Initialized PORT {}")\
               .format(fnl(), AST[0], group_port[current_group]))

    elif tag(AST) == 'certfile' :
      c = e (AST[1])                      # E.g. gold.crt.pem or "/etc/ups/keys/gold.cert.pem"
      try :              certfile[current_group] = msgs[c]  # Is this a name or a quotetext?
      except Exception : certfile[current_group] = c        # E.g. "/etc/ups/keys/gold.cert.pem"
      YYlogger('certfile: c = {} certfile[{}] = {}'\
               .format(c, current_group, certfile[current_group]))

    elif tag(AST) == 'monitors' :
      for i in AST[1:] : e (i)

    elif tag(AST) == 'monitor' :
      YYlogger('monitor: AST[1]={} AST[2]={} AST[3]={} AST[4]={} AST[5]={}'
               .format(AST[1], AST[2], AST[3], AST[4], AST[5]))
      fqups = ensure_fqups(e (AST[1]))
      current_ups = fqups                 # Used by LET battery.charge.low.i = number
      if fqups in powerval :
        msg=("{}[{},{}]  Error 410: UPS unit {} already specified.\n"\
            +tab+"I am ignoring this declaration.")\
            .format(confname, AST[0][1], AST[0][2], pp_ups(fqups))
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
      powerval[fqups] = int(e (AST[2]))   # E.g. 1
      upsduser[fqups] = e (AST[3])        # As declared in upsd.conf
      password[fqups] = e (AST[4])        # idem
      # Type should be 'primary' or 'secondary', previously 'master' or 'slave'
      # but for the moment we use master and slave internally
      try : raw_mastslav = {'primary':'master', 'secondary':'slave', 'master':'master', 'slave':'slave'}[e (AST[5])]
      except Exception : raw_mastslav = e (AST[5])
      if raw_mastslav in ['master','slave'] :
        mastslav[fqups] = raw_mastslav
        # Initialize UPS charge dictionary addressed by UPS fully qualified name name
        charge[fqups] = -1                # Charge not yet known
        battery_charge_low[fqups] = battery_charge_low_default # E.g. {1:50, 2:25, 3:12}
        for D in ('powerval','upsduser','password','mastslav') :
          v = globals()[D][fqups]
          YYlogger(('{}\n'\
                   +tab+'e ({},...) Initialized {}[{}]={}')\
                   .format(fnl(), AST[0], D,fqups,v))
      else:
        mastslav[fqups] = 'master'        # Error recovery
        charge[fqups] = -1                # Error recovery. Charge not yet known
        battery_charge_low[fqups] = battery_charge_low_default # E.g. {1:50, 2:25, 3:12}
        msg=('{}[{},{}]  Error 420: TYPE should be primary or secondary,\n'\
            +tab+'master or slave are tolerated, but not {}.\n'\
            +tab+'I am ignoring this declaration.')\
            .format(confname, AST[0][1], AST[0][2], raw_mastslav)
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable

    elif tag(AST) == 'minsupplies' :
      minsupplies[current_group] = int(e (AST[1]))
      DDlogger(("{}\n"\
                +tab+"e ({},...) Initialized MINSUPPLIES {}")\
                .format(fnl(), AST[0], minsupplies[current_group]))

    elif tag(AST) == 'action_declarations' :
      for i in AST[1:] : e (i)

    elif tag(AST) == 'action_declaration' :
      # ast = ('action_declaration', ('event_key',U,F,T), ('actions',...))
      event_key = e (AST[1])              # Returns e.g. LOCAL:Eaton@localhost:3493(OL,OB)
      actions = e (AST[2])                # Returns tuple (a1, a2, a3, ... ) where strings ai are actions
      # Add declarations to configuration
      # Append more actions to events[event_key] E.g. (((),EPRINT,'text'), (()SYSLOG,'text'), ...)
      try :                    events[event_key] = events[event_key] + actions   # Concatenation of actions
      except KeyError as err : events[event_key] = actions    # First actions specified for this event
      DDlogger(("{}\n"\
                +tab+"e ({},...) Updated events[{}] with \n"\
                +tab+"{}")\
                .format(fnl(), AST[0], event_key, actions))

    elif tag(AST) == 'event_key' :
      fqups = ensure_fqups(e (AST[1]))    # Ensures 'group:name@domain:port'
      if not fqups in powerval :
        msg=("{}[{},{}] Error 430: UPS unit '{}' has not been specified in a previous MONITOR declaration.\n"\
            +tab+"I am ignoring this declaration.")\
            .format(confname, AST[0][1], AST[0][2], fqups)
        logger(msg); eprinter(msg)
        #p[0] = 'event_key_error'         # ??? where does this line come from ???
        read_conf_rc = 1                  # This configuration not acceptable
      if AST[2] == 'TO' : event = (AST[2], e (AST[3]))  # E.g. ("TO", 'HB-timer')
      else :
        event = (AST[2], AST[3])          # E.g. ("OL","OB")
        if not event in events_decode_dict() :
          msg=('{}[{},{}] Error 440: UPS unit {}\n'\
              +tab+'Invalid EVENT status change {}->{}')\
              .format(confname, AST[0][1], AST[0][2], pp_ups(fqups), AST[2], AST[3])
          logger(msg); eprinter(msg)
          read_conf_rc = 1                  # This configuration not acceptable
      event_key = '{}{}'.format(fqups,event).replace(' ','') # E.g. string LOCAL:Eaton@localhost:3493(OL,OB)
      DDlogger(("{}\n"\
                +tab+"e ({},...)\n"\
                +tab+"Returned event_key {}")\
                .format(fnl(), AST[0], event_key))
      return event_key

    elif tag(AST) == 'actions' :
      actions = []
      for a in AST[1:] : actions.append(e (a))
      YYlogger(("{}\n"\
                +tab+"e ({},...)\n"\
                +tab+"Returned actions {}")\
                .format(fnl(), AST[0], actions))
      return actions

    # ('action_element', ((status,status), event_key, action_text))
    # returns an action.
    elif tag(AST) == 'action_element' :
      YYlogger(('{}\n'\
                +tab+'e ({},...)\n'\
                +tab+'len(AST)= {} AST[1]={}')\
                .format(fnl(), AST[0], len(AST), AST[1]))
      try : condition, action_keyword, raw_text = AST[1]
      except Exception as ex :
        msg=(('{}[{},{}] Error 450: I am unable to evaluate:\n'\
              +tab+'AST[1]= {}\n'\
              +tab+'Reason: {}\n'\
              +tab+'Exiting ...')\
              .format(confname, AST[0][1], AST[0][2], AST[1], ex))
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable
        YYlogger(('{}\n'\
                  +tab+'e ({},...)\n'\
                  +tab+'p_action_element returns (None, None, None)')\
                  .format(fnl(), AST[0]))
        return (None, None, None)
      YYlogger(('{}\n'\
                +tab+'e ({},...)\n'\
                +tab+'condition={}, action_keyword={}, raw_text={}')\
                .format(fnl(), AST[0], condition, action_keyword, raw_text))

      # Check the condition 2-tuple
      if condition == (None,None) : pass
      else :
        event = (condition[0], condition[1])  # E.g. ("OL","OB")
        YYlogger(('{}\n'\
                 +tab+'e ({},...)\n'\
                 +tab+'event={}, event in events_decode_dict() = {}')\
                 .format(fnl(), AST[0], event, event in events_decode_dict()))
        if not event in events_decode_dict() :
          msg="{}[{},{}] Error 460: Invalid IF status specification {}"\
              .format(confname, AST[0][1], AST[0][2], event)
          logger(msg); eprinter(msg)
          read_conf_rc = 1                # This configuration not acceptable
          condition = (None,None)         # E.g. LOCAL:Eaton@localhost:3493(OL,OB)
      # Within the tag 'action_element' we check all the possible action_keyword values
      # 'action_element : condition cancel_timer
      #                 | condition debug_level
      #                 | condition email
      #                 | condition start_timer
      #                 | condition EPRINT      quotetexts
      #                 | condition NOTIFY      quotetexts
      #                 | condition NUTLOG      quotetexts
      #                 | condition PRINT       quotetexts
      #                 | condition SETFSD      name
      #                 | condition SHELLCMD    quotetexts
      #                 | condition SHUTDOWNCMD quotetexts
      #                 | condition SYSLOG      quotetexts
      #                 | condition WALL        quotetexts'''

      # Look at all possible action_element values: (condition, action_keyword, raw_text)
      # Return action_text
      # (condition, 'cancel_timer', 'HB-timer')
      if action_keyword == 'cancel_timer' : action_text = e (raw_text)

      # (condition, 'debug_level', (('number', 53, 89), '2')
      elif action_keyword == 'debug_level' :
        raw_debug = int(e (raw_text))
        if raw_debug in [0, 1, 2] : pass
        else :
          msg=('{}[{},{}] Error 470: DEBUG {} error:\n'\
              +tab+'Value should be integer 0, 1 or 2, not {}\n'\
              +tab+'Exiting ...')\
              .format(confname, AST[0][1], AST[0][2], raw_text, raw_text)
          logger(msg); eprinter(msg)
          read_conf_rc = 1                # This configuration not acceptable
        action_text = '{}'.format(raw_debug)

      # email has raw_text as a 4-tuple.  Test the substitutions.
      # This is just a test.  The real substitutions happen in function do_action when some event occurs.
      # Reminder: condition, action_keyword, raw_text = AST[1]
      elif action_keyword == 'email' :
        From    = e(raw_text[0])
        To      = e(raw_text[1])
        Subject = e(raw_text[2])
        Content = e(raw_text[3])
        YYlogger(('{}\n'\
                 +tab+'e ({},...)\n'\
                 +tab+'action_keyword={}, From={}, To={}, Subject={}, Content={}')\
                 .format(fnl(), AST[0], action_keyword, From, To, Subject, Content))
        action_text = (From, To, Subject, Content)

      # (condition, 'start_timer', raw_text
      # where raw_text=((('name', 40, 39), 'two-min'), (('number', 40, 47), '120'))
      elif action_keyword == 'start_timer' :   # No more than a pass-through
        name = e (raw_text[0]) ; number = e (raw_text[1])
        action_text = (name, number)

      # (condition, 'SETFSD', ('name',('my-ups1')))
      # SETFSD: check that ups's have been defined
      elif action_keyword == "SETFSD" :
        action_text = ()
        for r in raw_text[1] :
          u = ensure_fqups(r)
          # Is this a known UPS unit ?
          if u in mastslav :
            action_text = action_text + (u,)     # ('my-ups1', 'my-ups2') + ('my-ups3',)
          else :
            msg=('{}[{},{}] Error 480: SETFSD error:\n'\
                +tab+'UPS unit {} not in previous MONITOR declaration.\n'\
                +tab+'Exiting ...')\
                .format(confname, AST[0][1], AST[0][2], pp_ups(u))
            logger(msg); eprinter(msg)
            read_conf_rc = 1              # This configuration not acceptable

      elif action_keyword in ('EPRINT', 'NOTIFY', 'NUTLOG', 'PRINT',
                              'SHELLCMD', 'SHUTDOWNCMD', 'SYSLOG', 'WALL') :
        # Sanity check on raw_texts format
        if (isinstance(raw_text, tuple)) and (raw_text[0][0] == 'quotetexts') : pass
        else :
          msg=('{}[{},{}] Error 500: action_element format error:\n'\
               +tab+"Format should be (('quotetexts', line, col), (text1, text2, ...))\n"\
               +tab+'not raw_text = {}\n'\
               +tab+'Exiting ...')\
              .format(confname, AST[0][1], AST[0][2], raw_text)
          logger(msg); eprinter(msg)
          read_conf_rc = 1                # This configuration not acceptable

        # Are the % substitutions correct ?  This is just a test.  The real substitutions
        # happen in function do_action when some event occurs.
        for a in raw_text[1] :
          YYlogger(('{}\n'\
                   +tab+'e ({},...)\n'\
                   +tab+'trying {} % {} ...')\
                   .format(fnl(), AST[0], a, adornment))
          try : ignore = a % adornment
          except KeyError as err :
            msg=('{}[{},{}] Error 360 Invalid use of a %(var)s expression\n'\
                +tab+'raw_text = {}\n'\
                +tab+'Error: {}\n'\
                +tab+'Hint: Valid variables in % expressions are {}')\
                .format(confname, AST[0][1], AST[0][2], raw_text, err.args, [v for v in adornment])
            logger(msg); eprinter(msg)
            read_conf_rc = 1              # This configuration not acceptable

        # Build action_text from raw-text tuple ('quotetexts', (text1, text2, ...))
        first = True
        for r in raw_text[1] :
          try :              t = msgs[r]  # Resolve MESSAGE
          except Exception : t = r
          if first : action_text = t ; first = False
          else :     action_text = action_text + '\n' + t    # String concatenation
        YYlogger(('{}\n'\
                 +tab+'e ({},...)\n'\
                 +tab+'resolves raw_text to action_text = {}')\
                 .format(fnl(), AST[0], action_text))

        # Within the quotetexts group, check the syslog levels in SYSLOG action_text
        if action_keyword == "SYSLOG" :   # This must match what is done in function syslogger
          m = re.match(r'^(\[(?P<a>[a-z]+)\])?.*',action_text)
          if m :                          # Tag found, check it
            if m.group('a') in ['emerg','alert','crit','err','warning','notice','info','debug'] : pass
            else :
              msg=('{}[{},{}] Error 510: Invalid SYSLOG priority tag [{}]\n'\
                  +tab+'action_text = {}\n'\
                  +tab+'Hint: Valid tags : [emerg], [alert], [crit], [err], [warning], [notice], [info], [debug].\n'\
                  +tab+'      Omitting the tag implies priority [info].')\
                  .format(confname, AST[0][1], AST[0][2], m.group('a'), action_text)
              logger(msg); eprinter(msg)
              read_conf_rc = 1            # This configuration not acceptable

      else :                              # Internal error
        action_text = raw_text
        msg=('{}[{},{}] Error 520: Invalid raw_text {} has type {}\n'\
            +tab+'AST[1]={}')\
            .format(confname, AST[0][1], AST[0][2], raw_text, type(raw_text), AST[1])
        logger(msg); eprinter(msg)
        read_conf_rc = 1                  # This configuration not acceptable

      # Build the action_element result
      c_ak_at = (condition,action_keyword,action_text)      # E.g. tuple ((.,.),'PRINT','Hello World')
      YYlogger(('{}\n'\
               +tab+'e ({},...)\n'\
               +tab+'p_action_element returns\n'\
               +tab+'{}')\
               .format(fnl(), AST[0], c_ak_at))
      return c_ak_at                      # Tuple of strings ((),'PRINT','Hello World')

    else :
      msg=('{}\n'\
          +tab+'Function e ({}) : argument error\n'\
          +tab+'tag (AST) = \'{}\' not supported.  Sorry.\n'\
          +tab+'Exiting ...')\
          .format(fnl(), AST, tag(AST))
      logger(msg); eprinter(msg)
      read_conf_rc = 1                    # This configuration not acceptable

  ###########################################################################################
  # Pretty print the syntax tree
  def is_tag (t) :
    if isinstance(t, tuple) :
      if len(t) == 3 :
        if isinstance(t[0], str) :
          if isinstance(t[1], int) :
            if isinstance(t[2], int) : return True
    else : return False

  def pp_AST (AST,indent='') :
    if AST == () :
      Ylogger('{}{}'.format(indent,AST))
    elif is_tag(AST) :
      Ylogger('{}{}'.format(indent,AST))
    elif isinstance(AST, tuple) :
      for a in AST[:] :
        pp_AST(a, indent+'| ')
    elif isinstance(AST, str) :
      Ylogger('{}"{}"'.format(indent,AST))
    else :
      Ylogger('{}{}'.format(indent,AST))

  ###########################################################################################
  # Build the lexer
  read_conf_rc = 0                        # Set to 1 if error detected
  lex_debug = debugYacc>0
  try : lexer = lex.lex(debug=lex_debug, debuglog=PLYlog)       # Build lexer
  except Exception as ex :
    msg = ('{} Error 530: PLY unable to build lexer:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...')\
           .format(blob, ex)
    logger(msg); eprinter(msg)
    read_conf_rc = 1                      # This configuration not acceptable

  lexer.linepos = lexer.lexpos            # See "maintaining state" in PLY doc

#  # What happened ?  Tokens have attributes tok.type, tok.value, tok.lineno, and tok.lexpos.
#  for t in lexer :
#    YYlogger('{}[{},{}] type="{}" value="{}"'\
#             .format(confname, t.lineno//LN, t.lineno%LN, t.type, t.value))

  # Build the parser  yacc.yacc also takes options errorlog=yacc.NullLogger(),
  # outputdir = "mydir", debug=True
  yacc_debug = debugYacc>0
  try : parser = yacc.yacc(start='configuration', debug=yacc_debug,
                           debuglog=PLYlog, write_tables=False)
  except Exception as ex :
    msg = ('{} Error 540: PLY unable to build parser:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...')\
           .format(blob, ex)
    logger(msg); eprinter(msg)
    read_conf_rc = 1                      # This configuration not acceptable

  # Read the entire configuration file
  with open(conffile) as cf :             # End of block closes file
    Dlogger ("Opening file {} for parser ...".format(cf.name))
    file = cf.read()                      # Read entire file into memory as string

  # Run lexer and parser to produce global AST, the abstract syntax tree
  try : yacc.parse(file,lexer=lexer,tracking=True)   # Run lexer and parser
  except Exception as ex :
    msg = ('{} Error 550: PLY yacc exception:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...')\
           .format(blob, ex)
    logger(msg); eprinter(msg)
    read_conf_rc = 1                      # This configuration not acceptable

  if read_conf_rc == 0 :
    Ylogger('AST =')
    pp_AST (AST, '  ')
    e (AST)                               # Interpret the abstract syntax tree
    if read_conf_rc == 0 : return 0
    else : return 1
  else : return 1

#############################################################################################
# Log the current configuration as single text with light tabbing 
def Dconfig_logger() :
  nl = "\n   "
  t = 'Configuration global variables...'
  t = t + nl + '   upsd_map: {} entries'.format(len(upsd_map))
  for u in upsd_map :
    t = t + nl + '{} {} \t{}'.format(" "*6, u, upsd_map[u])
  t = t + nl + '   grs             {}'.format(grs)
  t = t + nl + '   msgs: {} entries'.format(len(msgs))
  for m in msgs :
    t = t + nl + '{} {} \t{}'.format(" "*6, m, msgs[m])
  t = t + nl + '   powerval        {}'.format(powerval)
  t = t + nl + '   upsduser        {}'.format(upsduser)
  t = t + nl + '   upsd_sock       {}'.format(upsd_sock)
  t = t + nl + '   upsd_TLS        {}'.format(upsd_TLS)
  t = t + nl + '   password        {}'.format("* "*len(password))   # One * per ups
  t = t + nl + '   mastslav        {}'.format(mastslav)
  t = t + nl + '   battery_charge_low: {} entries'.format(len(battery_charge_low))
  for u in battery_charge_low :
    t = t + nl + '{} {} \t{}'.format(" "*6, u, battery_charge_low[u])
  t = t + nl + '   events: event_key and corresponding actions ... {} events'.format(len(events))
  for key in events :
    t = t + nl + '{} {}  {} actions'.format(" "*6, key, len(events[key]))
    for act in events[key] :
      t = t + nl + '{} {}'.format(" "*12, act)
  t = t + nl + '   pollfreq =      {}'.format(pollfreq)
  t = t + nl + '   pollfreqalert = {}'.format(pollfreqalert)
  t = t + nl + '   certfile: {} entries'.format(len(certfile))
  for c in certfile :
    t = t + nl + '{} {} \t{}'.format(" "*6, c, certfile[c])
  t = t + nl + '   minsupplies =   {}'.format(minsupplies)
  t = t + nl + '   group_fqups =   {}'.format(group_fqups)
  t = t + nl + '   group_host =    {}'.format(group_host)
  t = t + nl + '   group_port =    {}'.format(group_port)
  t = t + nl + '   SMTP_Server =   {}'.format(SMTP_Server)
  t = t + nl + '   SMTP_Port =     {}'.format(SMTP_Port)
  t = t + nl + '   SMTP_User =     {}'.format(SMTP_User)
  if isinstance(SMTP_Pass, str) : msg = "*"*len(SMTP_Pass)
  else :                      msg = "None"
  t = t + nl + '   SMTP_Pass =     {}'.format(msg)
  t = t + nl + '   shell =         {}'.format(shell)
  t = t + nl + '   conf_mtime =    {}'.format(conf_mtime)
  t = t + nl + '...end of configuration global variables:'
  Dlogger(t)
  return 0

#############################################################################################
# Log the current state if option -D
def Dstate_logger() :
  Dlogger('Configuration state variables...')
  Dlogger('   charge =        {}'.format(charge))
  Dlogger('   status =        {}'.format(status))
  Dlogger('   ALARMNone =     {}'.format(ALARMNone))
  Dlogger('   BOOSTNone =     {}'.format(BOOSTNone))
  Dlogger('   BYPASSNone =    {}'.format(BYPASSNone))
  Dlogger('   CALNone =       {}'.format(CALNone))
  Dlogger('   CHRGNone =      {}'.format(CHRGNone))
  Dlogger('   DISCHRGNone =   {}'.format(DISCHRGNone))
  Dlogger('   FSDNone =       {}'.format(FSDNone))
  Dlogger('   LBNone =        {}'.format(LBNone))
  Dlogger('   LB1None =       {}'.format(LB1None))
  Dlogger('   LB2None =       {}'.format(LB2None))
  Dlogger('   LB3None =       {}'.format(LB3None))
  Dlogger('   LSNone =        {}'.format(LSNone))
  Dlogger('   COMMNOCOMM =    {}'.format(COMMNOCOMM))
  Dlogger('   OFFNone =       {}'.format(OFFNone))
  Dlogger('   OLOB =          {}'.format(OLOB))
  Dlogger('   OVERNone =      {}'.format(OVERNone))
  Dlogger('   RBNone =        {}'.format(RBNone))
  Dlogger('   TESTNone =      {}'.format(TESTNone))
  Dlogger('   TICKNone =      {}'.format(TICKNone))
  Dlogger('   TOCKNone =      {}'.format(TOCKNone))
  Dlogger('   TRIMNone =      {}'.format(TRIMNone))
  Dlogger('   active_timers = {}'.format(active_timers))
  Dlogger('   raw_status_list_TO = {}'.format(raw_status_list_TO))
  Dlogger('...end of configuration state variables:')
  return 0

#############################################################################################
# Build directory upsd_map with entries
# {..., (ups_domain1,ups_port1):(group1,name1,certfile1),
#       (ups_domain2,ups_port2):(group2,name2,certfile2), ...}
# Note that if a upsd instance manages multiple UPS units, only one of these units will
# be recorded in the directory.  Not very elegant, but simple.
# To be run immediately after function read_conf.
# Returns 0 if successful, 1 otherwise.
def build_upsd_map () :
  # Scan though all the known UPS units while building directory upsd_map
  for fqups in powerval :
    m = re.match(re_fqups,fqups)
    if not m :
      msg=("{} Error 560: Internal error: Unable to decode fqups {}.\n"\
          +tab+"Exiting ...").format(blob, fqups)
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
    ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
    # Duplicate keys? Use the most recently defined. But check the certfiles.
    try :
      (g,n,c) = upsd_map[(ups_domain, ups_port)]
      # This domain:port already defined
      if c == certfile[ups_group] : pass
      else :
        msg = ("{} Error 570: CERTFILE confusion: the domain:port {}:{} has\n"\
              +tab+"already been assigned CERTFILE {} .\n"\
              +tab+"In the GROUP declaration {},\n"\
              +tab+"you are now trying to define a different CERTFILE {}\n"\
              +tab+"for this same domain:port.  Exiting.")\
              .format(blob, ups_domain, ups_port, c, ups_group, certfile[ups_group])
        logger(msg); eprinter(msg)
        return 1
    except Exception : pass               # First time we see this domain:port
    upsd_map[(ups_domain,ups_port)] = (ups_group, ups_name, certfile[ups_group])
  return 0

#############################################################################################
# Function do_command takes a command and its options in a list of strings,
# and returns stdout, stderr as iterable list of lines of utf-8 text.
# The command may be specified as a list of strings or as a single string.
# E.g. stdout, stderr = do_command(['/bin/bash', '-s', 'ls', '-alF'])
#      stdout, stderr = do_command('ls -l .'])
#      if not stdout == None :
#        for line in stdout :
# If error, logs message before returning stdout and stderr.
# It would be better to use shlex.split(command_line_string)
def do_command (L, use_shell=False) :
  Dlogger('{} do_command({}, use_shell={}) type(L)={} ...'\
          .format(fnl(), L, use_shell, type(L)))
  try:
    # Execute the command
    RC = subprocess.Popen(L, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=use_shell)
    bstdout, bstderr = RC.communicate()
    DDlogger('... bstdout =\n{} bstderr = {}'\
             .format(bstdout.decode('utf-8'), bstderr.decode('utf-8')))
    if bstdout == None : stdout = None
    else : stdout = re.split('\n',bstdout.decode("utf-8"))     # Convert bytes to iterable lines of text
    if bstderr == None : stderr = None
    # Convert bytes to iterable lines of text and remove '' elements from list
    else : stderr = [x for x in re.split('\n',bstderr.decode("utf-8")) if x != '']
    # Handle error output from command
    if stderr != [] :
      Dlogger('do_command stderr[0]={}'.format(stderr[0]))
      if stderr[0][:8] == 'We trust' :
        msg = (('{} Warning 580: do_command receives warning message when calling\n'\
               +tab+'{}\n'\
               +tab+'stderr = {}\n'\
               +tab+'Continuing ...')\
               .format(blob, string_list_to_string(L), stderr))
        logger(msg) ; eprinter(msg)
      else :
        msg = (('{} Error 585: do_command receives error message when calling\n'\
               +tab+'{}\n'\
               +tab+'stderr = {}\n'\
               +tab+'Continuing ...')\
               .format(blob, string_list_to_string(L), stderr))
        logger(msg) ; eprinter(msg)
    return stdout, stderr                 # Official exit from this function
  # Subprocess problems
  except Exception as ex :
    msg = ('Error 590: do_command error: Unable to execute command\n'\
           '\t {}\n'\
           '\t Reason: {}\n'\
           '\t Continuing ...')\
           .format(L, ex)
    logger(msg) ; eprinter(msg)
    return None, None

#############################################################################################
# As do_command, but with a different technique
def do_command2(L) :
  DDlogger('do_command2: command = {}'.format(L))
  try :
    reply = subprocess.check_output(L, stderr=subprocess.STDOUT)
    for ps_line in re.split(b'\n',reply) :
      DDlogger('Check - ps_line = {}'.format(ps_line))
      # Convert ps_line bytes to unicode
      l = re.findall('\w+',ps_line.decode('utf-8')) # pylint: disable=anomalous-backslash-in-string
      DDlogger('Check - l = {}'.format(l))
      if prog_name in l :
        msg = ("{} Error 611: a previous instance of {} is already\n"\
               +tab+"running for user = {}, group = {}, pid = {}, ppid = {} .\n"\
               +tab+"Please stop the previous instance first.\n"\
               +tab+"Exiting.")\
               .format(blob, prog_name, l[0], l[1], l[2], l[3])
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
  except subprocess.CalledProcessError as e1 :
    msg = ("{} Error 612: Unable to execute command\n"\
           +tab+"{}\n"\
           +tab+"Reason: {}\n"\
           +tab+"Exiting.")\
           .format(blob, L, e1)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  except OSError as e2 :
    msg = ("{} Error 613: Unable to execute command\n"\
           +tab+"{}\n"\
           +tab+"Reason: {}\n"\
           +tab+"Exiting.")\
           .format(blob, L, e2)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

#############################################################################################
# Define handler for SIGTERM, SIGHUP, SIGUSR1
def SIG_handler(signum, frame) :
  logger('{} Message 615: Signal handler called with signal {}'\
         .format(blob, signum))
  if signum == signal.SIGTERM :
    SIG_called['TERM'] = True             # Not used
    # Shut down
    logger('{} Message 616: Shutting down on signal {}'\
           .format(blob, signum))
    cleanup(); exit(0)
  elif signum == signal.SIGHUP :
    SIG_called['HUP'] = True
  elif signum == signal.SIGUSR1 :
    SIG_called['USR1'] = True
  else :
    logger('{} Error 617: Cannot handle signal {}.  Ignoring.'\
           .format(blob, signum))

#############################################################################################
# Function string_list_to_string takes a list of strings and returns the elements as a string
# with interspacing blanks.  E.g. ["Hello", "World"] -> "Hello World"
def string_list_to_string (L, sep=' ') :
  if len(L) == 0 : return ''
  elif len(L) == 1 : return L[0]
  else :
    S = L[0]
    for x in L[1:] : S += sep+x
    return S

# Function bytes_list_to_bytes takes a list of byte sequences and returns the elements as a byte
# sequence with interspacing blanks.  E.g. [b"Hello", b"World"] -> b"Hello World"
def bytes_list_to_bytes (L, sep=b' ') :
  if len(L) == 0 : return b''
  elif len(L) == 1 : return L[0]
  else :
    B = L[0]
    for x in L[1:] : B += sep+x
    return B

#############################################################################################
# Send command given as string on socket s to upsd and return the rc and the response as string.
# Parameter timeout is the timeout for the socket to upsd.
# Return code: 0=successful, 1=no bytes sent, 2=send socket exception, 3=send other exception,
#              4=recv socket exception 5=recv other exception
# Errors from upsd have form "ERR TOKEN" with rc=0.
# Received and returned string do not include \n
# Manage the 'no reply' from upsd which leads to COMM/NOCOMM status for a UPS identified
# in 3rd argument.
# E.g. rc, reply = send_cmd('VER', domain, port, timeout)
# Inject 'COMM' or 'NOCOMM' into raw_status_list for fqups
# COMMNOCOMM = {..., fqups:'COMM'|'NOCOMM',...}             # Current value before status change
# raw_status_COMMNOCOMM = {..., fqups:'COMM'|'NOCOMM',...}  # New status
def send_cmd (command, domain, port, timeout) :
  try :
    l=1; fqups = fqups_build(domain, port)
    l=2; s = upsd_sock[(domain, port)]
  except Exception as ex :
    msg=(('{} Error 620: Internal error: l={}\n'\
          +tab+'send_cmd({},{},{},{})\n'\
          +tab+'Reason: {}\n'\
          +tab+"Exiting ...")\
          .format(blob, l, command, domain, port, timeout, ex))
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

  # Ensure that sent command is terminated by one single \n and is in byte form
  if isinstance(command, str) : byte_cmd = bytes(no_trailing_newlines(command)+'\n','utf-8')
  else :                        byte_cmd = no_trailing_newlines(command)+b'\n'
  # I want True or False not some Python wierdness
  is_list_cmd = boolean(re.match(b'^LIST\s', byte_cmd)) # pylint: disable=anomalous-backslash-in-string
  Dlogger('send_cmd sending {} via {} to {} ...'\
          .format(pp_msg(byte_cmd), pp_sock(s), pp_ups(fqups)))
  try :
    byte_count = s.send(byte_cmd)         # Returns number of bytes sent
    if byte_count > 0 :       rc = 0
    else :                    rc = 1 ; ex = 'zero bytes sent'  # upsd dead?
  except socket.error :       rc = 2 ; ex = 'socket.error'
  except Exception :          rc = 3 ; ex = 'Problem in send_cmd'
  if rc > 0 and raw_status_COMMNOCOMM[fqups] == 'NOCOMM' :
    return (rc,'')                        # (1,'') or (2,'')
  elif rc > 0 :
    raw_status_COMMNOCOMM[fqups] = 'NOCOMM'   # Maybe bad news for raw_status_list
    logger(('{} Error 630: Socket error {}\n'\
            +tab+'when talking to UPS {}\n'\
            +tab+'rc = {}  Generating COMM->NOCOMM event for UPS {}\n'\
            +tab+'This error message will not be repeated as long as UPS {}\n'\
            +tab+'has status NOCOMM.  Continuing ...')\
            .format(blob, ex, pp_ups(fqups), rc, pp_ups(fqups), pp_ups(fqups)))
    return (rc,'')                        # (1,'') or (2,'')
  else :
    raw_status_COMMNOCOMM[fqups] = 'COMM'   # Maybe good news for raw_status_list
    DDlogger('send_cmd sent {} via {} to {}'\
             .format(pp_msg(command), pp_sock(s), pp_ups(fqups)))

  # Try for a reply
  reply = ''
  try :
    raw_reply = recv_response(s, is_list_cmd, timeout)  # An elabotate s.recv
    reply = no_trailing_newlines(raw_reply.decode('utf-8'))
    if reply == '' :
      rc = 5 ; reply = 'NOCOMM'
      raw_status_COMMNOCOMM[fqups] = 'NOCOMM' # Maybe bad news for raw_status_list
      Dlogger('... send_cmd: rc = {}, raw_status_COMMNOCOMM[{}] = {}'\
              .format(rc, pp_ups(fqups), raw_status_COMMNOCOMM[fqups]))
    else :
      rc = 0
      raw_status_COMMNOCOMM[fqups] = 'COMM' # Maybe good news for raw_status_list
      DDlogger('... send_cmd: rc = {}, raw_status_COMMNOCOMM[{}] = {}'\
               .format(rc, pp_ups(fqups), raw_status_COMMNOCOMM[fqups]))
  except Exception as ex :                # Socket is dead.
    if COMMNOCOMM[fqups] == 'COMM' :
      msg=('{} Error 640: Socket error: {}\n'\
           +tab+'timeout {} sec,\n'\
           +tab+'after sending {}.\n'\
           +tab+'This socket to UPS {} will now have status NOCOMM.\n'\
           +tab+'Continuing ...')\
           .format(blob, ex, s.gettimeout(), pp_msg(command), pp_ups(fqups))
      logger(msg); eprinter(msg)
    raw_status_COMMNOCOMM[fqups] = 'NOCOMM'   # Maybe bad news for raw_status_list
    rc = 4; reply = 'NOCOMM'              # More bad news for raw_status_list
  DDlogger('send_cmd: rc = {}, reply {}, closing socket {}'\
           .format(rc, pp_msg(reply), pp_sock(s)))
#  s.close()                               # One man, one vote. One command, one socket.
#  del upsd_sock[(domain, port)]           # Forget that this upsd uses this socket
  return (rc, reply)                      # (n, '...')

# Function recv_response receives a reponse.
# LIST command: loops until it receives END LIST
# Not a LIST command: assume one and one only response message.
# Returns raw data as received.
# The -D option will log the exit code.
def recv_response (s, is_list_cmd, timeout) :
  Dlogger('Function recv_response({},{},{})'.format(pp_sock(s), is_list_cmd, timeout))
  s.setblocking(False)                    # Ensure socket is non blocking
  s.settimeout(timeout)                   # Ensure socket is non blocking
  total_data=[]                           # total_data received into a list of chunks
  chunk=''
  chunk_count = 0                         # How many non-empty chunks do we get ?
  begin = time.time()                     # Used for debugging
  exit_code = -10                         # Reason for deciding that we have seen the whole response

  # Loop indefinitely until either END LIST received, or once only if not a LIST command
  while True :
    chunk_count = chunk_count + 1         # Counting those chunks
    try :
      chunk = s.recv(buf_size)
      type_chunk = type(chunk)            # For debugging
      len_chunk = len(chunk)              # For debugging
      total_data.append(chunk)            # Next piece of the list
      if is_list_cmd :                    # LIST command ?
        is_last_line = boolean(re.search(b'END LIST\s', chunk)) # pylint: disable=anomalous-backslash-in-string
        Dlogger(('recv_response receives response from socket {}\n'\
                 +tab+'LIST chunk number {} length {} type {} is_last_line={}\n'\
                 +tab+'{}')\
                 .format(pp_sock(s), chunk_count, len_chunk,\
                         type_chunk, is_last_line, pp_msg(chunk, max=200)))
        if is_last_line :
          exit_code = chunk_count
          break
        else : continue
      else :
        Dlogger(('recv_response receives response from socket {} length {} type {}\n'\
                 +tab+'{}')\
                 .format(pp_sock(s), len_chunk, type_chunk, pp_msg(chunk, max=200)))
        exit_code = 0
        break
    except socket.timeout :
      exit_code = -1
      Dlogger('recv_response socket.timeout is_list_cmd={} chunk_count={} exit_code={}'\
              .format(is_list_cmd, chunk_count, exit_code))
      break
    except Exception as ex:
      exit_code = -2
      msg=('{} Error 310: socket.recv error:\n'\
           +tab+'socket {}\n'\
           +tab+'Reason: {}\n'\
           +tab+'Continuing ...')\
           .format(blob, pp_sock(s, long=True), ex)
      logger(msg); eprinter(msg)

  # Join up the chunks to make hopefully complete response
  result = bytes_list_to_bytes(total_data, b'') # Join with no spacer
  elapsed_time = time.time() - begin      # How long did the recv take ?
  Dlogger(('recv_response received {} chunks in {:.3f} secs,'\
           ' exit_code={}')\
           .format(chunk_count, elapsed_time, exit_code))
  return result

# Function no_trailing_newlines removes all trailing newlines from a string,
# and returns a string.  Works for byte strings.
def no_trailing_newlines (string) :
  if isinstance(string, str) : return string.rstrip ('\n')
  else : return string.rstrip (b'\n')

#############################################################################################
# Send an e-mail
# Server, Port, User and Pass are taken from the global variables
# See https://realpython.com/python-send-email/
# Receives "('Joe@localhost', 'Jane@localhost', 'UPS on fire', '...')"
def emailer (F_T_S_M) :
  if SMTP_Server==None or SMTP_Port==None or SMTP_User==None or SMTP_Pass==None :
    msg=('{} Error 660: emailer error: SMTP Server, Port, User, Pass\n'\
        +tab+'must be specified in configuration file,\n'\
        +tab+'not SMTP_Server={}, SMTP_Port={}, SMTP_User={}, SMTP_Pass={}\n'\
        +tab+'Continuing ...')\
        .format(blob,SMTP_Server,SMTP_Port,SMTP_User,SMTP_Pass)
    logger(msg); eprinter(msg)
    return 1
  # Extract From, To, Suject and content from argument
  try :
    From_key, To_key, Subject, content = F_T_S_M
    Dlogger(('emailer: SMTP_Server={}, SMTP_Port={}, SMTP_User={}, SMTP_Pass={}\n'\
             +tab+'emailer(({},\n'\
             +tab+'{},\n'\
             +tab+'{},\n'\
             +tab+'{}))')\
             .format(SMTP_Server, SMTP_Port, SMTP_User, SMTP_Pass,
                     From_key, To_key, Subject, content))
  except Exception :
    msg=('{} Error 670: emailer error:\n'\
        +tab+'I expected a string containing a four element tuple such as\n'\
        +tab+'("Joe@localhost", "Jane@localhost", "UPS on fire", "...")\n'\
        +tab+'but I found {}\n'\
        +tab+'Continuing ...')\
        .format(blob, F_T_S_M)
    logger(msg); eprinter(msg)
    return 1
  content = 'Subject: '+Subject+'\n\n'+content

  # Use default secure SSL context.  Explicit context creation fails
  # with "unable to get local issuer".
  # Using "with" provides automatic close.  Removed context=context
  with smtplib.SMTP_SSL(host=SMTP_Server, port=SMTP_Port) as s :
    rc = s.login(SMTP_User, SMTP_Pass)
    Dlogger(('emailer login {} pass {} to {}:{}\n'\
             +tab+'rc={}')\
             .format(SMTP_User, SMTP_Pass, SMTP_Server, SMTP_Port, rc))
    content = 'User-Agent: {} Version {}\n'\
              '    using OpenSSL version {}\n'\
              '    in Python {}\n'\
              'To: {}\n'\
              '{}'\
              .format(fnl(), Version, ssl.OPENSSL_VERSION,\
                      sys.version.replace('\n', ' '), To_key, content)
    # Ensure content is 7-bit ascii
    ascii = ''.join([chr(min(126,ord(c))) for c in content])
    Dlogger(('emailer trying s.sendmail({},{},\n'\
             +tab+'{}) ...')\
             .format(From_key, To_key, ascii))
    try : rc = s.sendmail(From_key, To_key, ascii)
    except smtplib.SMTPRecipientsRefused as err :
      msg=('{} Error 680: emailer error when calling Python s.sendmail:\n'\
           +tab+'From={}, To={}, ascii={} refused:\n'\
           +tab+'{}\n'\
           +tab+'Continuing ...')\
           .format(blob, From_key, To_key, ascii, err.args)
      logger(msg); eprinter(msg)
    except Exception as ex :
      msg=('{} Error 690: emailer error when calling Python s.sendmail:\n'\
           +tab+'From={}, To={}, ascii={} refused:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Continuing ...')\
           .format(blob, From_key, To_key, ascii, ex)
      logger(msg); eprinter(msg)
    logger(('emailer s.sendmail({},\n'\
            +tab+'{},\n'\
            +tab+'ascii)\n'\
            +tab+'returns rc={}')\
           .format(From_key, To_key, rc))

#############################################################################################
# notifier
# Send notifications to all X display users.
# Assumes that /etc/sudoers allows the caller to sudo as any user.
# E.g. nut LAN = (ALL) NOPASSWD:SETENV: /usr/bin/notify-send
# Call with message as string parameter.
# See https://unix.stackexchange.com/questions/2881/show-a-notification-across-all-running-x-displays

# The message is displayed to each X display user using notify-send
# with the notify-send options fixed at "-t 0 -u critical".

# Assumes that /etc/sudoers allows the caller to sudo as any user.
# E.g. nut LAN = (ALL) NOPASSWD:SETENV: /usr/bin/notify-send
# where LAN is defined by a declaration such as
# Host_Alias LAN = 10.218.0/255.255.255.0,127.0.0.1,localhost
# To update /etc/sudoers use visudo: for example
#    VISUAL=/usr/bin/emacs visudo -f /etc/sudoers
def notifier (message) :
  Dlogger('{} notifier({}) type(message)={}'.format(fnl(), message, type(message)))
  if not isinstance(message, str) :
    msg=('{} Error 695: notifier parameter must be a string, not {}\n'\
         +tab+'Continuing ...')\
         .format(blob, type(message))
    logger(msg); eprinter(msg)
    return 1
  # Send who output to stdout and read the lines sent back
  stdout, stderr = do_command (["who"])
  if stderr != [] : return 1
  # E.g. line = "rprice console 2019-08-17 16:04 (:0)" with ":" for X display user
  for line in stdout :
    DDlogger('notifier: who reports line = {}'.format(line).strip())
    line_split = re.split('\s',line.strip()) # pylint: disable=anomalous-backslash-in-string
    user_name, display = line_split[0], line_split[-1]  # display must contain a :
    DDlogger('notifier: user_name={} display={}'.format(user_name, display))
    m = re.match('\((:.*)\)',display) # pylint: disable=anomalous-backslash-in-string
    if m :
      display = 'DISPLAY="{}"'.format(m.group(1))    # E.g. DISPLAY=":0"
      command_list = [sudo, '-u', user_name, display, notify_send, '"'+message+'"']
      command_string = ' '.join(command_list)
      Dlogger(('notifier: issuing command_list\n'\
               +tab+'{} len={}\n'\
               +tab+'command_string = {} len={}\n'\
               +tab+'use_shell={}')\
               .format(command_list, len(command_list), command_string, len(command_string), True))
      # For some reason I do not understand, the program notify-send executes but does not
      # produce an on-screen window if I set use_shell=False.  I suspect a Gnome problem.
      stdout, stderr = do_command (command_string, use_shell=True)   # Function do_command handles errors

# Following code works
def notifier_bak (message) :
  options = '-t 0 -u critical'    # Options for notify-send
  try :
    # Send who output to stdout and read it back
    p = subprocess.Popen(["who"], stdout=subprocess.PIPE)
    # E.g. line = "rprice console 2019-08-17 16:04 (:0)" with ":" for X display user
    for line in io.TextIOWrapper(p.stdout, encoding="utf-8") :
      Dlogger('notifier: who reports: {}'.format(line).strip())
      line_split = re.split('\s',line.strip())  # pylint: disable=anomalous-backslash-in-string
      user_name, display = line_split[0], line_split[-1]  # display must contain a :
      m = re.match('\((:.*)\)',display) # pylint: disable=anomalous-backslash-in-string
      if m :
        display = m.group(1)
        banner = '{}@{}'.format(getpass.getuser(), hostname)
        command = 'sudo -u {} DISPLAY="{}" {} {} "[{}] {}"'\
                  .format(user_name, display, notify_send, options, banner, message)
        Dlogger('notifier: issuing command {}'.format(command))
        rc = os.system(command)
        DDlogger('notifier: rc = {}'.format(rc))
  except FileNotFoundError as err :     # No "who" command available
    msg=('{} Error 700: notifier error when using Python subprocess.Popen(["who"])\n'\
         +tab+'{}\n'\
         +tab+'Continuing ...')\
         .format(blob, err.args)
    logger(msg); eprinter(msg)

#############################################################################################
# syslogger sends text message to syslog with optional priority.
# E.g. syslogger('[crit] my_msg')
# Priority levels (high to low):
# LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.
# Default priority is LOG_INFO
# Syslog levels: emerg, alert, crit, err, warning, notice, info, debug
def syslogger (message) :
  priority_dict = {'emerg':syslog.LOG_EMERG, 'alert':  syslog.LOG_ALERT,   'crit':  syslog.LOG_CRIT,
                   'err':  syslog.LOG_ERR,   'warning':syslog.LOG_WARNING, 'notice':syslog.LOG_NOTICE,
                   'info': syslog.LOG_INFO,  'debug':  syslog.LOG_DEBUG}
  m = re.match(r'^(\[(?P<a>emerg|alert|crit|err|warning|notice|info|debug)\])?[\ \t]*(?P<b>.*)',message)
  if m.group('a') : priority = priority_dict[m.group('a')]; content = m.group('b')
  else :            priority = syslog.LOG_INFO;             content = message
  try : syslog.syslog (priority, content)
  except Exception as ex :
    msg=('{} Error 710: syslogger error when using Python\n'\
         +tab+'syslog.syslog({},{})\n'\
         +tab+'Reason: {}')\
        .format(blob, priority, content, ex)
    logger(msg); eprinter(msg)

#############################################################################################
# Function set_FSD (fqups_tuple) is used by the master to order it's slaves to shutdown.
# The command are latched up by upsd.
# The slaves are expected to shutdown immediately on receiving the corresponding None->FSD event.
def set_FSD (fqups_tuple) :
  for fqups in fqups_tuple :
    ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
    # Is this a known UPS unit ?
    if fqups in mastslav :
      Dlogger('set_FSD ({}) ... mastslav[{}]={}'.format(pp_ups(fqups), pp_ups(fqups), mastslav[fqups]))
    else :
      msg=('{} Error 720: SETFSD "{}" error:\n'\
          +tab+'UPS unit {} not in previous MONITOR declaration.\n'\
          +tab+'Continuing ...')\
          .format(blob, pp_ups(fqups), pp_ups(fqups))
      logger(msg); eprinter(msg)
      return 1

    # Sanity check - is fqups a slave?
    if mastslav[fqups] == 'slave' :
      Dlogger('set_FSD: sending FSD to upsd for slave {}'.format(pp_ups(fqups)))
      rc, reply = send_cmd('FSD {}'.format(ups_name), ups_domain, ups_port, upsdtimeout)
      m = re.match(r'.*OK.*',reply)
      if not m :
        msg=('{} Error 730: set_FSD({}) error: \"FSD {}\" request refused for user {}.\n'\
             +tab+'Continuing ...')\
             .format(blob, pp_ups(fqups), ups_name, upsduser[fqups])
        logger(msg); eprinter(msg)
        return 1
    else :                                # No FSD to be sent to master
      msg=('{} Error 740: set_FSD error: FSD should be signalled to secondaries (slaves),\n'\
           +tab+'not the primary (master) {}.\n'\
           +tab+'Continuing ...')\
           .format(blob, pp_ups(fqups))
      logger(msg); eprinter(msg)
      return 1

#############################################################################################
# Function fqups_explode(fqups) returns group, name, domain, port
def fqups_explode (fqups) :
  m = re.match(re_fqups,fqups)
  if not m :
    msg=("{} Error 750: Internal error: Unable to decode fqups {}.\n"\
        +tab+"Exiting ...").format(blob, fqups)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  group = m.group(1)                      # E.g. LOCAL  (Group not used in sockets)
  name = m.group(2)                       # E.g. Eaton
  domain = m.group(3)                     # E.g. localhost
  port = m.group(4)                       # E.g. 3493
  return (group, name, domain, port)

# Function fqups_build(domain, port) returns a fqups string e.g. 'HB:Eaton@localhost:401'
def fqups_build (domain, port) :
  if (domain, port) in upsd_map :
    (group, name, certfile) = upsd_map[(domain, port)]
    return group + ':' + name + '@' + domain + ':' + port
  else : return 'Unknown:Unknown@' + domain + ':' + port

#############################################################################################
# set_debug sets the value of global variable debug
def set_debug (d=0) :
  global debug # pylint: disable=global-statement
  old_debug = debug                       # For debug log message
  if isinstance(d, int) : debug = d
  elif isinstance(d, str) :
    try : debug = int(d)
    except Exception as ex :
      msg=("{} Error 770: set_debug error: value should be '0', '1' or '2', not {}.\n"\
          +tab+'Reason: {}')\
          .format(blob, d, ex)
      logger(msg); eprinter(msg)
      return 1
  else :
    msg=("{} Error 780: set_debug error: value should be '0', '1' or '2', not {}.\n"\
        +tab+"Continuing ...")\
        .format(blob, d)
    logger(msg); eprinter(msg)
    return 1
  Dlogger('set_debug: debug value changed from {} to {}'\
          .format(old_debug, debug))

#############################################################################################
# do_shellcmd  Function uses the command supplied as a string in the argument.
# Given shell = '/bin/bash -c' and do_shellcmd('echo "Hello World"')
# execute ['/bin/bash',  '-c', 'echo "Hello World"']
def do_shellcmd (shellcmd) :
  L = [x for x in re.split('\s+',shell) if x!=''] + [shellcmd] # pylint: disable=anomalous-backslash-in-string
  logger('{} Message 790: do_shellcmd: executing do_command ({}) ...'\
         .format(blob, L))
  stdout, stderr = do_command (L)         # Function do_command handles errors

#############################################################################################
# do_shutdown  Function uses the command supplied as first argument to shut down the system
# SHUTDOWNCMD '/sbin/shutdown -h +0'
def do_shutdown (shutdowncmd) :
  L = [sudo, '-u', 'root'] + [x for x in re.split('\s+',shutdowncmd) if x!=''] # pylint: disable=anomalous-backslash-in-string
  logger('{} Message 800: do_shutdown: executing do_command ({}) ...'\
         .format(blob, L))
  stdout, stderr = do_command (L)         # Function do_command handles errors

#############################################################################################
# waller
# Use wall to send messsage to all terminal users.
# Assumes that /etc/sudoers allows the caller to sudo as any user.
# E.g. nut LAN = (ALL) NOPASSWD:SETENV: /usr/bin/wall
# Call with message as parameter.
# Assumes that /etc/sudoers allows the caller to sudo as any user.
# E.g. nut LAN = (ALL) NOPASSWD:SETENV: /usr/bin/wall
# where LAN is defined by a declaration such as
# Host_Alias LAN = 10.218.0/255.255.255.0,127.0.0.1,localhost
# To update /etc/sudoers use visudo: for example
#    VISUAL=/usr/bin/emacs visudo -f /etc/sudoers
# See also
# https://serverfault.com/questions/814769/how-to-silently-broadcast-a-warning-from-a-cronjob-via-wall
# wall option -n avoids 'wall: cannot get tty name: Inappropriate ioctl for device'
def waller (message) :
  # Ensure text of message is 7-bit ascii
  ascii = ''.join([chr(min(126,ord(c))) for c in message])
  # Take care of those nasty mesages that include " characters which upset shlex
  command = shlex.split('sudo -u root ' + wall + ' "' + ascii.replace('"','') + '"')
  Dlogger('waller: issuing command {}'.format(command))
  stdout, stderr = do_command (command)  # Function do_command handles the errors

#############################################################################################
# Funtion start_timer uses the Python timer facilities
# timer_name_n is a tuple, n is an integer number of seconds
# active_timers is a dictionary {..., name:timer, ...}
def start_timer (timer_name_n) :
  timer_name, n = timer_name_n ; n = int(n) # Extract name and number
  DDlogger(('start_timer({})  with type {}, timer_name = {}, n = {}.\n'\
           +tab+'Timer({},time_out,args=[{}]), active_timers = {}')\
           .format(timer_name_n, type(timer_name_n), timer_name, n,
                   n, timer_name, active_timers))
  t = Timer(n,time_out,args=[timer_name])  # Use Python timer
  t.start()                                # Start Python timer
  active_timers[timer_name] = t            # Remember that we have this timer running
  Dlogger ("start_timer: active_timers = {}".format(active_timers))
  return

#  Add timeout status change to raw_status_list  via raw_status_list_TO
def time_out (timer_name) :
  raw_status_list_TO.append('TO({})'.format(timer_name))
  try :
    del active_timers[timer_name]          # Remove timer from dictionary
  except KeyError as err :                 # Not in dictionary
    msg=('{} Error 810: time_out error {}\n'\
         +tab+'Active timers = {}\n'\
         +tab+'Continuing ...')\
         .format(blob, err.args, active_timers)
    logger(msg); eprinter(msg)
  Dlogger (('time_out: timer_name = {}, raw_status_list_TO = {}\n'\
            +tab+'active_timers = {}')\
            .format(timer_name, raw_status_list_TO, pp_active_timers(active_timers)))
  return

def cancel_timer (timer_name) :
  DDlogger ("cancel_timer: timer_name = {}, active_timers = {} ..."\
            .format(timer_name, active_timers))
  try :
    t = active_timers[timer_name]
    t.cancel()                             # Cancel Python timer
    del active_timers[timer_name]          # Remove timer from dictionary
    Dlogger ("cancel_timer: timer_name = {}, active_timers = {}"\
             .format(timer_name, active_timers))
  except KeyError as err :                 # Not in dictionary
    msg=('{} Warning 830:\n'\
         +tab+'You are cancelling a non-existent timer called {}\n'\
         +tab+'This may happen at the startup of a heartbeat sequence,\n'\
         +tab+'or when power returns during a shutdown sequence.\n'\
         +tab+'Active timers = {}\n'\
         +tab+'Continuing ...')\
         .format(blob, timer_name, active_timers)
    logger(msg); eprinter(msg)
  except Exception as ex :
    msg=('{} Error 820: cancel_timer error\n'\
         +tab+'Reason: {}\n'\
         +tab+'When trying to cancel timer {}.\n'\
         +tab+'Active timers = {}\n'\
         +tab+'Continuing ...')\
         .format(blob, ex, timer_name, active_timers)
    logger(msg); eprinter(msg)
  return rc

#############################################################################################
# Function get_battery_charge returns current charge as an integer, or 999 if no data from upsd
def get_battery_charge (fqups) :
  ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
  rc, reply = send_cmd('GET VAR {} battery.charge'.format(ups_name), ups_domain, ups_port, upsdtimeout)
  Dlogger('get_battery_charge({}) GET VAR {} battery.charge: rc=«{}»  reply=«{}»'\
          .format(fqups, ups_name, rc, reply))
  # Do we still have contact with upsd ?
  if (reply == 'NOCOMM') | (reply[0:3] == 'ERR') :
    return 999                            # UPS cannot or does not provide battery.charge value
  else :
    m = re.match(r'VAR\s*[\w=_.-]+\s*battery.charge\s\"(\d+)\"',reply)
    if m : return int(m.group(1))
    else :
      msg = ('{} Error 1245: UPS {}: Unable to parse battery.charge: {}'\
             +tab+'Continuing...')\
             .format(blob, pp_ups(fqups), reply)
      logger(msg); eprinter(msg)
      return 999

#############################################################################################
# Function do_action takes a fully qualified UPS and an event and executes the required actions
# The event is a 2-tuple such as (None,'BOOST') or ('COMM','NOCOMM')
# The action definitions are provided by the user in the configuration file.  The actions
# include an "action text" which takes two forms:
# A string such as 'message'   e.g. part of (cond,'PRINT', 'Hello')
# A tuple such as ('HB-timer', 20) e.g. part of (cond,'STARTTIMER', ("HB-timer", 20))
# A tuple such as ('bla', 'bla', 'bla', 'bla')  e.g. part of (cond, 'email', ('bla', 'bla', 'bla', 'bla'))
def do_action(fqups, event) :
  # Get this UPS unit's current charge from upsd's battery.charge
  charge[fqups] = get_battery_charge(fqups)
  ch = charge[fqups]                       # Charge of this ups
  Dlogger ('ddd do_action 1 fqups={}, event={}, charge={}'.format(pp_ups(fqups), event, ch))

  # See https://realpython.com/python-string-formatting/ for the four styles of string formatting
  # The string.format style is #2:
  pp_event='{}->{}'.format(event[0],event[1])
  banner = '{}@{}'.format(getpass.getuser(), hostname)
  # The formatting style is #1 with variable substitutions by name.  Here is the RHS:
  named_values = {'u':pp_ups(fqups), 'c':ch, 'e':pp_event, 'b':banner, 'h':hostname}
  # Get list of actions
  events_index = fqups+str(event).replace(' ','')     # Events index is a string with no spaces
  try : action_list = events[events_index]
  except KeyError : action_list = []
  Dlogger ('ddd do_action 2 action_list = {}'.format(action_list))
  for condition, action_keyword, action_text in action_list :
    Dlogger(('ddd do_action 3 {}{}: condition = {}, action_keyword = {},\n'\
             +tab+'action_text = {}   type(action_text) =  {}')\
            .format(pp_ups(fqups), event, condition, action_keyword,
                    action_text, type(action_text)))
    # Is the condition satisfied?
    if condition == (None,None) : pass
    else :
      event = (condition[0],condition[1])             # E.g. ('BOOST',None)
      D = events_decode_dict()[event][0]              # E.g. BOOSTNone dicionary
      target = condition[1]                           # E.g. 'OL'
      if globals()[D][fqups] != target :
        Dlogger('ddd do_action 4 condition D={}, event={} target={}: False, ignoring this action'\
               .format(D,event,target))
        continue

    # Pick out the required action execution function
    try : f = action_keyword_dict()[action_keyword]
    except Exception as ex :   # Dictionary error
      msg=('{} Error 830: do_action dictionary error:\n'\
           +tab+'Cannot find action_keyword = {} in dictionary keywords\n'\
           +tab+'{}\n'\
           +tab+'Reason: {}\n'\
           +tab+'Continuing ...')\
           .format(blob, action_keyword, [x for x in action_keyword_dict()], ex)
      logger(msg); eprinter(msg)
      return 1

    # Yes, there is now an action_text with type integer
#    if type(action_text) == int :
#      DDlogger('do_action 4 {}{}: type(action_text)={}'\
#               .format(pp_ups(fqups), event, type(action_text)))
#      action_text_with_values = action_text

    # Separate the simple text actions and the complex tuples
    # First the simple strings ...
    if isinstance(action_text, str) :
      Dlogger(('ddd do_action 5 {}{}: attempting action_text % named_values ...\n'
                +tab+'{} % {}')\
                .format(pp_ups(fqups), event, action_text, named_values))
      # Expand action_text to include arguments fqups, charge, event and banner
      # Typical usage is 'Hello UPS %(ups)s' % {'ups':fqups, 'ch':charge, 'ev':event}
      # to produce 'Hello UPS cheapo'
      action_text_with_values = action_text % named_values

      # The action, e.g. start_timer, do_shutdown, is put to work, 
      Dlogger('ddd do_action 6 {}{}: action_keyword = {}, action_text_with_values = {}'\
              .format(pp_ups(fqups), event, action_keyword, action_text_with_values))
      try : f(action_text_with_values)
      except Exception as ex :   # This does not catch problems in the called function
        msg=('{} Error 840: do_action error when attempting to execute\n'\
             +tab+'{}({})\n'\
             +tab+'Reason: {}\n'\
             +tab+'Continuing ...')\
             .format(blob, f, action_text_with_values, ex)
        logger(msg); eprinter(msg)
        return 1
      continue

    # Separate the simple text actions and the complex tuples
    # ... and now the tuples
    if isinstance(action_text, tuple) :
      Dlogger('ddd do_action 10 {}{}: type(action_text)={} len(action_text)={}'\
              .format(pp_ups(fqups), event, type(action_text), len(action_text)))
      # Start timer is an irregular case with no % substitutions
      if action_keyword == 'start_timer' :  action_text_with_values = action_text
      else :
        # Expand action_text to include arguments fqups, charge, event and banner
        # ('my_timer',3) => ('my_timer' % {'ups':fqups, 'ch':charge, 'ev':event}, 3)
        # ('From...', 'To...', 'Subj...', 'content')
        action_text_with_values = ()              # Build up tuple
        for a in action_text :
          action_text_with_values = action_text_with_values + (a % named_values,)

      Dlogger('ddd do_action 7 {}{}: action_keyword = {}, action_text_with_values = {}'\
              .format(pp_ups(fqups), event, action_keyword, action_text_with_values))
      # Execute the action  e.g. email(From, To, Subject,content)
      try : f(action_text_with_values)
      except Exception as ex :   # This does not catch problems in the called function
        msg=('{} Error 850: do_action error when attempting to execute\n'\
             +tab+'{}({})\n'\
             +tab+'Reason: {}\n'\
             +tab+'Continuing ...')\
             .format(blob, f, action_text_with_values, ex)
        logger(msg); eprinter(msg)
        return 1
      continue

    # Martian data
    else :
      msg=('{} Error 860: do_action error: Martian data, type(action_text) = {}\n'\
          +tab+'Continuing ...')\
          .format(blob, type(action_text))
      logger(msg); eprinter(msg)
      return 1
    continue

#############################################################################################
# Function safe_get (dictionary,key,default=None) returns dictionary[key] if it exists.
# otherwise sets dictionary[key] = default, and returns default
# Both arguments must be strings e.g. safe_get('BOOSTNone','heartbeat@localhost:3493')
def safe_get (dictionary, key, default=None) :
  try :
    # We try to access the required element, expecting an exception.
    # We don't use eval which is considered dangerous.
    D = globals()[dictionary]; v = D[key]
    return v
  except KeyError as err :   # key is also in err.args[0]
    D[key] = default
    DDlogger('safe_get setting and returning {}[{}] = {} ...'\
             .format(dictionary, key, default))
    return default
  except Exception as ex :
    msg=('{} Error 870: safe_get error when attempting to evaluate action\n'\
         +tab+'{}[{}]\n'\
         +tab+'Reason: {}\n'\
         +tab+'Exiting ...')\
         .format(blob, dictionary, key, ex)
    logger(msg); eprinter(msg)
    exit(1)

#############################################################################################
# Cleanup on program exit
# What happens if there is no log file?
def cleanup() :
  cleanup_logger('Cleaning up ...')
  # Clean up the upsd logins
  # Clean up the sockets to upsd
  for (ups_domain, ups_port) in upsd_sock :
    (ups_group, ups_name, certfile) = upsd_map[(ups_domain, ups_port)]
    fqups = fqups_build(ups_domain, ups_port)
    s = upsd_sock[(ups_domain, ups_port)]
    cleanup_logger ('Logging out from socket {} to {}...'\
                    .format(pp_sock(s), pp_ups(fqups)))
    rc, reply = send_cmd('LOGOUT', ups_domain, ups_port, upsdtimeout)
    cleanup_logger ('Closing socket {} to {} ...'\
                    .format(pp_sock(s, long=True), pp_ups(fqups)))
    s.close()
  # Clean up current timers: active_timers is a dictionary {..., name:timer, ...}
  # Python does not allow modification of a dictionary during an iteration
  active_timer_names = [t for t in active_timers]  # so we iterate through a copy
  for t in active_timer_names :
    cleanup_logger ('Closing timer {} ...'.format(t))
    cancel_timer (t)
  # All cleaned up
  cleanup_logger('{} morituri te salutant {}\n'.format('#'*32, '#'*32))
  # Close log file
  try : log.close()                       # Close if open, also closes stdout, stderr
  except Exception : pass

# What happens if there is no log file?
def cleanup_logger(line) :
  # Does the log file exist?
  try :
    # Log file exists, we do logger's job
    rc = log.write('{} {} {}\n'.format(tod(),fnl(),line))
    log.flush()                           # Get output into file
  except Exception :
    # No logging available, print to stderr
    eprinter (line)

#############################################################################################
# Does an executable program exist?
# https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def is_executable (fpath):
  return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

#############################################################################################
#############################################################################################
#                                    Main program                                           #
#############################################################################################
#############################################################################################
try :              hostname = socket.gethostname()     # Name of the machine running UPSmon
except Exception : hostname = 'UPSmon'
prog_name = re.split('/',str(sys.argv[0]))[-1]  # Name of this program  E.g. UPSmon.py
TLHB = u"\u2E22"        # Unicode Top Left Half Bracket ⸢
TRHB = u"\u2E23"        # Unicode Top Right Half Bracket ⸣
BLHB = u"\u2E24"        # Unicode Bottom Left Half Bracket ⸤
BRHB = u"\u2E25"        # Unicode Bottom Right Half Bracket ⸥
UpArrow = u"\u21B1"	# UPWARDS ARROW WITH TIP RIGHTWARDS 21B1 ↱
DownArrow = u"\u21B3"	# DOWNWARDS ARROW WITH TIP RIGHTWARDS 21B3 ↳
mlsb = '⟦'              # MATHEMATICAL LEFT WHITE SQUARE BRACKET (U+27E6, Ps)
mrsb = '⟧'              # MATHEMATICAL RIGHT WHITE SQUARE BRACKET (U+27E7, Pe):
lcb = '⦃'               # LEFT WHITE CURLY BRACKET (U+2983, Ps): ⦃
rcb = '⦄'               # RIGHT WHITE CURLY BRACKET (U+2984, Pe): ⦄
lsb = '⸨'               # LEFT DOUBLE PARENTHESIS (U+2E28, Ps): ⸨
rsb = '⸩'               # RIGHT DOUBLE PARENTHESIS (U+2E29, Pe): ⸩
lob = '﴾'               # ORNATE LEFT PARENTHESIS (U+FD3E, Ps): ﴾
rob = '﴿'               # ORNATE RIGHT PARENTHESIS (U+FD3F, Pe): ﴿
fullblock = '█'         # FULL BLOCK (U+2588)
blob = fullblock*2
buf_size = 8192         # string buffer size for socket.recv

# Configuration
AST = ()                # Abstract syntax tree
run_as_user = None      # After launch, run as this user
conf_date = 0           # Seconds since Unix began

upsd_map = {}           # Directory of UPS's providing (group,name,certfile) for each upsd's
                        # (domain,port).  See build_upsd_map for more detail.
grs = []                # List of groups declared in configuration file
msgs = {}               # Dictionary of name:text  E.g. msgs['msg.1'] = "Hello"
msgs['hostname'] = hostname  # Built in named message
# Addressed by fully qualified ups name e.g. 'LOCAL:Eaton@localhost:3493'
powerval = {}           # How many systems protected by each UPS
                        # Also used as a list of UPS units.
upsduser = {}           # User name as declared in upsd.users
password = {}           # User's password as declared in upsd.users
# For the moment 'primary' and 'secondary' are permissable alternatives for 'master'and 'slave'
mastslav = {}           # Primary/secondary, master/slave as declared in upsd.users
certfile = {}           # Python TLS requires explicit file for public key. Dict indexed by group name.
events = {}             # Event dictionary keyed by string <ups>(<event_l>,<event_r>),
                        # with corresponding values = list [(cond,KEYWORD,text), ...]

# Since the logger may be called before the log file is opened
# we need a flag to say when the log file is available.
log_file_open = False

# An identifier for the Linux OS
OS_id = get_OS_id()
# Try to guess the non-root user and the configuration directories.
default_user, etc_dir = get_NUT_install_params ()  # E.g. ('debian', '/etc/nut')

# Default values.  See argparser for more default values.
pollfreq = 5            # Same as upsmon
pollfreqalert = 5       # Same as upsmon
#powerdownflag = '/etc/killpower2'  # Same as upsmon
#rbwarntime = 43200      # Same as upsmon
#nocommtime = 300        # Same as upsmon
minsupplies = {}        # Dictionary addressed by group e.g. {'LOCAL': 1}
group_host = {}         # Dictionary addressed by group e.g. {'LOCAL': 'localhost'}
group_port = {}         # Dictionary addressed by group e.g. {'LOCAL': 3493}
group_fqups = {}        # Dictionary addressed by group {..., group:[fqups1, ...], ...}

SMTP_Server = None      # E.g. mail.example.com
SMTP_Port = None        # E.g. 587 Assumes TLS required
SMTP_User = None        # E.g. mailbox@mail-provider.tld
SMTP_Pass = None        # E.g. sekret

conf_mtime = 0          # Most recent modification time
upsd_sock = {}          # Each upsd has a socket permanently open.  Addressed by (domain, port).
upsd_TLS = {}           # Each upsd has TLS working, True/False.  Addressed by (domain, port).
charge = {}             # Each ups has a battery.charge value or -1
battery_charge_low = {} # Each UPS has an entry of form {1:50, 2:25, 3:12}, a software version of [LB]
#battery_charge_low_default = {1:50, 2:25, 3:12}     # Default [LBi] i=1..3
battery_charge_low_default = {1:92, 2:90, 3:88}     # Default [LBi] i=1..3

# Stuff that needs to be global
poll_number = 0         # 1, 2, ... for each poll
# The internal SIGFSD signal calls for shutdown.  upsmon.c uses SIGUSR1
# The SIGTERM handler is used to terminate the loop.  upsmon.c uses SIGTERM
# The SIGHUP handler is used to re-read configuration file.  upsmon.c uses SIGHUP
SIG_called = {'USR1':False, 'TERM':False, 'HUP':False}
# Flags and indicators shared by read_conf and it's functions
current_group = None                    # GROUP declaration will provide value
current_ups = None                      # MONITOR declaration will provide value
read_conf_rc = 0                        # Set >0 if configuration errors found
# When daemonised, divert stdout and stderr to log file.
stderr_redirect = False

# Dictionary of protocol number -> protocol name used in log messages
protocol_names = {ssl.PROTOCOL_TLS:'PROTOCOL_TLS',
                  ssl.PROTOCOL_TLS_SERVER:'PROTOCOL_TLS_SERVER',
                  ssl.PROTOCOL_TLS_CLIENT:'PROTOCOL_TLS_CLIENT',
#                  ssl.PROTOCOL_SSLv3:'PROTOCOL_SSLv3', # No longer available
#                  ssl.PROTOCOL_SSLv2:'PROTOCOL_SSLv2', # No longer available
                  ssl.PROTOCOL_TLSv1_2:'PROTOCOL_TLSv1_2',
                  ssl.PROTOCOL_TLSv1_1:'PROTOCOL_TLSv1_1',
                  ssl.PROTOCOL_TLSv1:'PROTOCOL_TLSv1'}

# Take a look at the user's calling options
# Define argument type which will be a function name
def arg_file_a (file) :                   # File must be appendable
  try :
    with open(file, 'a') as fd : pass     # The with will close fd
  except Exception :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
           +tab+'File specification error: {} is not appendable for {}.\n'\
           +tab+'Please check your file and directory permissions.')\
           .format(file, user)
    raise argparse.ArgumentTypeError(msg)
  return file

def arg_file_e (file_args) :              # File must be executable
  file = re.split(r'\s', file_args)[0]    # Split off the arguments
  if pathlib.Path(file).exists() : pass
  else :
    msg = ('\n'\
           +tab+'File specification error: {} does not exist on this machine.')\
           .format(file)
    raise argparse.ArgumentTypeError(msg)
  if is_executable (file) : pass
  else :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
          +tab+'File specification error: {} exists but is not executable for {}.\n'\
          +tab+'Please check your file and directory permissions.')\
          .format(file, user)
    raise argparse.ArgumentTypeError(msg)
  return file_args

def arg_file_r (file) :                   # File must be readable
  if pathlib.Path(file).exists() : pass
  else :
    msg = ('\n'\
           +tab+'File specification error: {} does not exist on this machine.')\
           .format(file)
    raise argparse.ArgumentTypeError(msg)
  try :
    with open(file, 'r') as fd : pass     # The with will close fd
  except Exception :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
           +tab+'File specification error: {} exists but is not readable for {}.\n'\
           +tab+'Please check your file and directory permissions.')\
           .format(file, user)
    raise argparse.ArgumentTypeError(msg)
  return file

# Only root can specify the user.  User must be valid in local system.
def arg_user (user) :                     # Typically nut or upsd
  myuid = os.getuid()                     # uid of caller
  if myuid != 0 :
    msg = ('\n'\
           +tab+'Only root can specify the user, and you are not root.')
    raise argparse.ArgumentTypeError(msg)
  try :
    run_as_user = pwd.getpwnam(user)[0:4] # E.g. ('upsd', 'x', 478, 2)
  except KeyError as err :
    msg=('\n'\
        +tab+'User specification error.  User "{}" not known.\n'\
        +tab+'Maybe somewhere else, but not here.  Sorry.')\
        .format(user)
    raise argparse.ArgumentTypeError(msg)
  return user

argparser = argparse.ArgumentParser(
  description='UPSmon.py is a Python3 script which monitors and manages local'
              '  and remote NUT installations.'
              '  Status: "experimental".  Intended for demonstration and experiment.',
  epilog='License: GPL v3 or later at your choice.\n'
         'Support: nut-user mailing list.\n'
         'Documentation: http://rogerprice.org/NUT/ConfigExamples.A5.pdf')
argparser.add_argument('--command',          nargs=1, choices=['fsd','reload','stop'],
                       help='Send command to UPSmon process and exit.'\
                            '  Valid commands are %(choices)s.',
                       metavar='fsd|reload|stop')
argparser.add_argument('--config', '-c',     nargs=1, type=arg_file_r,
                       default=etc_dir+'UPSmon.conf',
                       help='Configuration file, default %(default)s',
                       metavar='<file>')
argparser.add_argument('--debug', '-D',            action='count', default=0,
                       help='Increase the debugging level, may be repeated.')
argparser.add_argument('--debugYacc', '-Y',        action='count', default=0,
                       help='Increase the Lex Yacc debugging level, may be repeated.')
argparser.add_argument('--logfile', '-l',    nargs=1, type=arg_file_a,
                       default='/var/log/NUT.log',
                       help='Log file, default %(default)s',
                       metavar='<file>')
argparser.add_argument('--notify', '-n',     nargs=1, type=arg_file_e,
                       default='/usr/bin/notify-send -t 0 -u critical',
                       help='Notify executable, default %(default)s',
                       metavar='<executable>')
argparser.add_argument('--PIDfile',          nargs=1, type=str,
                       default='/run/nut/UPSmon.pid',
                       help='Pid file used by systemd, default %(default)s'\
                            ' Do not change this unless you know what you are doing.',
                       metavar='<file>')
argparser.add_argument('--shell',            nargs=1, type=str,
                       default='/bin/bash -c',
                       help='Which shell will process the action commands? Default = %(default)s',
                       metavar='<executable>')
argparser.add_argument('--sudo',             nargs=1, type=arg_file_e,
                       default='/usr/bin/sudo',
                       help='sudo executable, default %(default)s .'
                       ' Use of sudo assumes that file /etc/sudoers allows'
                       ' the caller to sudo as the required user. For example'
                       ' '+default_user+' LAN = (ALL) NOPASSWD:SETENV: /sbin/shutdown'
                       ' To update /etc/sudoers use visudo , for example'
                       ' VISUAL=/usr/bin/emacs visudo -f /etc/sudoers',
                       metavar='<executable>')
argparser.add_argument('--testSHUTDOWNflag', '-K', action='count', default=0,
                       help='Test the SHUTDOWN flag.  Not implemented.')
argparser.add_argument('--upsdtimeout',      nargs=1, type=float,
                       default=5.0,
                       help='Socket timeout for exchanges with upsd, default is %(default)s secs',
                       metavar='<float>')
argparser.add_argument('--user', '-u',       nargs=1, type=arg_user,
                       default=default_user,
                       help='After launch as root, run as this user, default is %(default)s',
                       metavar='<user>')
argparser.add_argument('--version', '-v',          action='version',
                       help='Show program, Python and SSL/TLS versions, then exit.',
                       version='%(prog)s {}, with SSL/TLS support: {}, '\
                               'running on Python {}'
                       .format(Version,ssl.OPENSSL_VERSION,sys.version.replace('\n',' ')))
argparser.add_argument('--wall', '-w',       nargs=1, type=arg_file_e,
                       # Option -n avoids 'wall: cannot get tty name: Inappropriate ioctl for device'
                       default='/usr/bin/wall -n',
                       help='wall executable, default %(default)s',
                       metavar='<executable>')
args = argparser.parse_args()
debug = args.debug
debugYacc = args.debugYacc
testSHUTDOWNflag = args.testSHUTDOWNflag

# Provide default values if arguments were omitted
if args.command == None : user_command = None
elif args.command[0] == 'fsd' :    user_command = 'fsd'   ; SIG_called['USR1'] = True; exit(0)
elif args.command[0] == 'reload' : user_command = 'reload'; SIG_called['HUP']  = True; exit(0)
elif args.command[0] == 'stop' :   user_command = 'stop'  ; SIG_called['TERM'] = True; exit(0)
# Python wierdness: if the option was specified by the user, the result is a string
# in a list, but if the default is used then the result is just the string.
#print('args.config={}'.format(args.config))   # r list!
#print('args.log={}'.format(args.log))         # a list!
#print('args.notify={}'.format(args.notify))   # e
#print('args.wall={}'.format(args.wall))       # e
conffile    = args.config[0]      if isinstance(args.config, list)  else args.config
shell       = args.shell[0]       if isinstance(args.shell, list)   else args.shell
log_file    = args.logfile[0]     if isinstance(args.logfile, list) else args.logfile # Change variable name -> log_file
PIDfile     = args.PIDfile[0]     if isinstance(args.PIDfile, list) else args.PIDfile
notify_send = args.notify[0]      if isinstance(args.notify, list)  else args.notify
try_user    = args.user[0]        if isinstance(args.user, list)    else args.user
wall        = args.wall[0]        if isinstance(args.wall, list)    else args.wall
sudo        = args.sudo[0]        if isinstance(args.sudo, list)    else args.sudo
upsdtimeout = args.upsdtimeout[0] if isinstance(args.upsdtimeout, list) else args.upsdtimeout

#############################################################################################
# UPS status dictionaries addressed by UPS fully qualified name
# known_statuses = [ 'ALARM', 'BOOST', 'BYPASS', 'CAL', 'CHRG', 'DISCHRG', 'FSD',
#                    'LB', 'LB1', 'LB2', 'LB3', 'LS', 'OB', 'OFF', 'OL',
#                    'OVER', 'RB', 'TRIM']  # Per drivers/dummy-ups.h and others
status = {}             # Current status reported by UPSD, before any status change, e.g. OB LB FSD
ALARMNone = {}          # Current ALARM status of each UPS, before any status change
BOOSTNone = {}          # Current BOOST status of each UPS, before any status change
BYPASSNone = {}         # Current BYPASS status of each UPS, before any status change
CALNone = {}            # Current CAL status of each UPS, before any status change
CHRGNone = {}           # Current CHRG status of each UPS, before any status change
DISCHRGNone = {}        # Current DISCHRG status of each UPS, before any status change
FSDNone = {}            # Current FSD status of each UPS, before any status change
LBNone = {}             # Current LB status of each UPS, before any status change
LB1None = {}            # Current LB1 status of each UPS, before any status change
LB2None = {}            # Current LB2 status of each UPS, before any status change
LB3None = {}            # Current LB3 status of each UPS, before any status change
LSNone = {}             # Current LS status of each UPS, before any status change
COMMNOCOMM = {}         # Current COMM/NOCOMM flipflop of each UPS, before any status change
OFFNone = {}            # Current OFF status of each UPS, before any status change
OLOB = {}               # Current OL/OB flipflop of each UPS, before any status change
OVERNone = {}           # Current OVER status of each UPS, before any status change
RBNone = {}             # Current RB status of each UPS, before any status change
TESTNone = {}           # Current TEST status of each UPS, before any status change
TICKNone = {}           # Current TICK/TOCK status of each UPS, before any status change
TOCKNone = {}           # Current TICK/TOCK status of each UPS, before any status change
TRIMNone = {}           # Current TRIM status of each UPS, before any status change
active_timers = {}      # Current timers, {..., name:timer, ...}
raw_status_list_TO = [] # Initialize list of '(TO,timer_name)'
raw_status_COMMNOCOMM = {} # Initialize directory {..., fqups:COMM|NOCOMM, ...}

# The values used by the dictionaries
dict_values = ['ALARM', 'BOOST', 'BYPASS', 'CAL', 'CHRG', 'DISCHRG', 'FSD',
               'LB', 'LB1', 'LB2', 'LB3', 'LS', 'OFF',
               'OB', 'OL', 'OVER', 'RB', 'TRIM', 'COMM', 'NOCOMM', None]
known_action_keywords = sorted([k for k in action_keyword_dict()] + ['IF', '=='])
re_action_keywords = "("      # Will become (NUTLOG|...|SYSLOG)
for k in known_action_keywords :
  re_action_keywords += k+"|"
re_action_keywords = re_action_keywords.strip("|") + ")"
# Include common errors
re_action_keywords_err = re_action_keywords.strip(")") + "|SHUTDOWNCMD)"

# The days go by
today = ""

# Useful regular expressions
re_fqups = r'([^:]+):([^@]+)@([^:]+):(.*)'    # Extract gr, name, domain and port (with possible event)
re_fqups_event = r'([^:]+):([^@]+)@([^:]+):([^\(]+)(\([^\)]+\))'  # Extract gr, name, domain, port and event
re_timer_name = r'[a-zA-Z0-9_\-.]+'           # Matches valid timer name

#############################################################################################
# Open a file for logging on behalf of calling user
calling_user = pwd.getpwnam(getpass.getuser())[0:4]     # E.g. ('jschmo', 'x', 2078, 3000)
log, log_inode = open_log_file(log_file, calling_user[2], calling_user[3])   # Opened for calling user
# Indent for continuation lines
tab = ' '*11                               # Somewhat arbitrary
# Kick off new session in the log file
logger('#' * 53 + '')
logger('#' * 53 + '')
msg = '{} Version {}, Python version {}'\
      .format(prog_name, Version, sys.version.replace('\n',' '))
logger(msg) ; syslogger(msg)
logger('nodename={} OS ID={} sysname={} release={} machine={}'\
       .format(os.uname().nodename, OS_id, os.uname().sysname, os.uname().release, os.uname().machine))
msg = 'ssl.OPENSSL_VERSION {}'.format(ssl.OPENSSL_VERSION)
logger(msg) ; syslogger(msg)
logger('This log file: {}, owner is {} with UID = {}, GID = {}'\
       .format(log_file, calling_user[0], calling_user[2], calling_user[3]))
logger('Log file notation: '+lsb+'...'+rsb+' is a socket to upsdTLS,')
logger('Log file notation: '+lob+'...'+rob+' is a TLS wrapped socket.')
msg = '{} starts with caller: {}@{}  PID: {}, UID = {}, GID = {}.'\
      .format(prog_name, calling_user[0], hostname, os.getpid(), calling_user[2], calling_user[3])
logger(msg) ; syslogger(msg)
syslogger('[notice] Further {} messages will be written in file {}'.format(prog_name, log_file))

logger("Caller's working directory: {}".format(os.getcwd()))
line='Calling command:'                   # Build up display of user's parameters
for x in sys.argv:
  line = line + " {}".format(str(x))
logger(line)

# We now work out who is run_as_user, the user who will be running this server.
# Only root can specify a user.
# For current user name: getpass.getuser()
# This code is fragile, and relies heavily on the checking carried
# out by type verification function arg_user.
fork = False                                    # Do we fork ?
logger('Determining which user will run the daemon {} ...'.format(prog_name))
Dlogger('os.getuid()={} args.user={}'.format(os.getuid(), args.user))
if os.getuid() == 0 :                           # root tries to set user
  run_as_user = pwd.getpwnam(try_user)[0:4]     # E.g. ('jschmo', 'x', 2078, 3000)
  if run_as_user == 'root' :
    fork = False
    msg='{} Warning 880: daemon {} will be run as user root.'\
        .format(blob, prog_name)
    logger(msg); eprinter(msg)
  else : fork = True
  logger('... root sets {} to run daemon {}'.format(run_as_user, prog_name))
else :                                          # Caller is not root
  run_as_user = pwd.getpwuid(os.getuid())[0:4]  # E.g. ('jschmo', 'x', 2078, 3000)
  fork = False
  logger('User {} will run daemon {}'.format(run_as_user, prog_name))

if calling_user[0] == run_as_user[0] :
  logger('... daemon {} will be run by calling user {}'.format(prog_name, calling_user[0]))
else :
  logger('... daemon {} will be run by {}'.format(prog_name, run_as_user[0]))

if fork :
  msg = ('Closing log file to re-open with user {}\n'\
         +tab+ '-' * 32)\
         .format(run_as_user[0])
  logger(msg)
  log.close()
  # Reopen a file for logging as the user who will run the server
  log, log_inode = open_log_file(log_file, run_as_user[2], run_as_user[3])   # Opened for run_as_user
  logger('{} client log file inode {} reopened for user {}'\
         .format(prog_name, os.stat(log_file).st_ino, run_as_user[0]))

# Check - are we running already as some other non-privileged user?
Dlogger('Checking - is daemon {} already running as {} ?'\
       .format(prog_name, run_as_user[0]))
# L = ['ps', '-u', run_as_user[0], '-o', 'euser,egroup,pid,ppid,comm', '--no-header']
L = ['ps', '-C', prog_name, '-o', 'euser,egroup,pid,ppid,comm', '--no-header']
Dlogger('Check - running command: {}'.format(L))
stdout, stderr = do_command (L)      # Unicode output or None
Dlogger(('Check looks at command output - \n'\
         +tab+'stdout = {}\n'\
         +tab+'stderr = {}').format(stdout, stderr))
is_previous_instance_running = False
if stderr != [] :
  msg = '{} Error 890: Internal error: STDERR:'.format(blob)
  logger(msg); eprinter(msg); is_previous_instance_running = True
  for line in stderr :
    logger(line); eprinter(line)     # Let's hear the bad news
elif stdout != None :
  for line in [x for x in stdout if x != ''] :
    DDlogger('Check - looking for {} in {}'.format(prog_name,line))
    # line already converted to unicode
    l = re.findall('[\w.-]+',line)  # pylint: disable=anomalous-backslash-in-string
    DDlogger('Check - tokens in line = {} have type {}'.format(l, type(l)))
    if l[0] != getpass.getuser() :   # Is this someone else ?
      DDlogger('Check - {} != {}'.format(l[0],getpass.getuser()))
      msg = ("{} Error 900: a previous instance of {} is already running\n"\
            +tab+"for user = {}, group = {}, pid = {}, ppid = {} .\n"\
            +tab+"Please stop this previous instance first, for\n"\
            +tab+"example with command 'killall -SIGTERM {}'\n"\
            +tab+"or 'killall -SIGKILL {}' if really needed.")\
            .format(blob, prog_name, l[0], l[1], l[2], l[3], prog_name, prog_name)
      logger(msg); eprinter(msg)
      is_previous_instance_running = True
      break
if is_previous_instance_running : cleanup(); exit(1)
else : logger('No previous instance of {} running'.format(prog_name))

# Define the SIGTERM handler used to terminate the loop.
signal.signal(signal.SIGTERM, SIG_handler)
# Define the SIGUSR1 handler used to re-read the configuration file.
signal.signal(signal.SIGUSR1, SIG_handler)
# Define the SIGHUP handler used to re-read configuration file.
signal.signal(signal.SIGHUP, SIG_handler)

# Read the configuration file and initialise global variables
rc = read_conf(conffile)                  # Initialise the configuration
if rc>0 :
  msg=("{} Message 920: Unable to read configuration from {}.\n"\
      +tab+"Exiting ...").format(blob, conffile)
  logger(msg); eprinter(msg)
  cleanup(); exit(1)
rc = build_upsd_map ()                    # Construct directory upsd_map
if rc == 0 : pass
else : cleanup(); exit(1)                 # build_upsd_map error

# To speed up the detection of status LS, build a dictionary of fqups in each group
# Dictionary group_fqups = {..., group:[fqups1, ...], ...}
for fqups in powerval :
  ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
  try : ups_list = group_fqups[ups_group]
  except Exception : ups_list = []
  ups_list.append(fqups)                  # Python wierdness
  group_fqups[ups_group] = ups_list

# Display configuration and current state
logger(('{} Message 930: Configuration successfully updated.\n'\
       +tab+'Use option -Y to see details of Lex and Yacc activity.')\
       .format(blob))

Dconfig_logger()                          # Debugging, log the configuration
Dstate_logger()                           # Log state globals if -D called

# Sanity checks for the configuration
logger('Sanity checks for this configuration ...')
# Check - for each group, have SHUTDOWNCMD actions been specified in the configuration file ?
# Check - for each group, is there an action for None->LB ?
# Check - for each group, is there an action for COMM->NOCOMM ?
for g in grs :
  shutdown_specified = 0
  None_LB_actions = 0
  COMM_NOCOMM_actions = 0
  for evkey in events :
    m = re.match(re_fqups_event,evkey)    # Extract group from group:name@domain:port(event)
    DDlogger('g={}  m.group(1)={}'.format(g, m.group(1)))

    if m.group(1) == g :
      for condition, keyword, text in events[evkey] :       # E.g. ((condition),'KEY',('short_timer',3))
        DDlogger('Searching for "SHUTDOWNCMD": keyword={} minsupplies={} type {}'\
                 .format(keyword, minsupplies[g], type(minsupplies[g])))
        if (keyword == "SHUTDOWNCMD") or (minsupplies[g] == 0) :
          shutdown_specified += 1

    DDlogger('Searching for (None,"LB"): m.group(1)={} m.group(5)={} minsupplies={}'\
             .format(m.group(1), m.group(5), minsupplies[g]))
    if ((m.group(1) == g) and (m.group(5) == "(None,'LB')")) or (minsupplies[g] == 0) :
      None_LB_actions += 1

    DDlogger('Searching for ("COMM","NOCOMM"): m.group(1)={} m.group(5)={} type={} minsupplies={}'\
             .format(m.group(1), m.group(5), type(m.group(5)), minsupplies[g]))
    if ((m.group(1) == g) and (m.group(5) == "('COMM','NOCOMM')")) or (minsupplies[g] == 0) :
      COMM_NOCOMM_actions += 1

  if shutdown_specified == 0 :
    msg = ('{} Warning 935: no SHUTDOWNCMD actions specified in group {}\n'\
          +tab+'which has MINSUPPLIES > 0 .  Please review configuration file\n'\
          +tab+'{}')\
          .format(blob, g, conffile)
    logger(msg); eprinter(msg)
  if None_LB_actions == 0 :
    msg = ('{} Warning 940: no action specified for event None->LB in group {}.\n'\
          +tab+'Please review configuration file\n'\
          +tab+'{}')\
          .format(blob, g, conffile)
    logger(msg); eprinter(msg)
  if COMM_NOCOMM_actions == 0 :
    msg = ('{} Warning 950: no action specified for event COMM->NOCOMM in group {}.\n'\
          +tab+'Please review configuration file\n'\
          +tab+'{}')\
          .format(blob, g, conffile)
    logger(msg); eprinter(msg)

  # Check - for each group, if the UPS is a slave, is there an action for None->FSD ?
  slave_FSD_specified = 0
  for evkey in events :
    m = re.match(re_fqups_event,evkey)    # Extract group from group:name@domain:port(event)
    if m.group(1) == g :
      FSD_fqups = '{}:{}@{}:{}'.format(m.group(1),m.group(2),m.group(3),m.group(4))
      if (mastslav[FSD_fqups] == 'slave') and (m.group(5) == '(None->FSD)') :
        slave_FSD_specified += 1
      if mastslav[FSD_fqups] == 'master' :
        slave_FSD_specified += 1          # FSD handling not needed in master
  if slave_FSD_specified == 0 :
    msg = ('{} Warning 960: Slave UPS {} in group {}.\n'\
          +tab+'No SHUTDOWNCMD action specified for event (None->FSD).\n'\
          +tab+'Please review configuration file\n'\
          +tab+'{}')\
          .format(blob, FSD_fqups, g, conffile)
    logger(msg); eprinter(msg)

# Check - Do all the UPS unit CERTFILE declarations point to a real file?
for fqups in powerval :
  ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
  Dlogger('Checking certfile[{}] ...'.format(ups_group))
  c = certfile[ups_group]
  try :
    with open(c, 'r') : pass              # CERTFILE readable?
  except Exception :
    msg=("{} Error 970: MONITOR declaration for UPS {}\n"\
        +tab+"Cannot open CERTFILE {}.\n"\
        +tab+"Exiting ...").format(blob, pp_ups(fqups), c)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

# Check - For each group, do we have enough "powervalues" to cover the minsupplies ?
#         Did the user blow off a foot as predicted by 2.7.4 upsmon.c 1812 ?
for g in grs :
  total_pv = 0
  for u in group_fqups[g] :               # Each fqups in the group
    total_pv += int(powerval[u])
  if total_pv < int(minsupplies[g]) :
    msg = ("{} Fatal error 990: Power value error in group {}.\n"\
          +tab+"Total power value {} is less than required MINSUPPLIES {}.\n"\
          +tab+"Impossible power configuration.  Unable to continue.\n"\
          +tab+'Please review configuration file\n'\
          +tab+'{}')\
          .format(blob, g, total_pv, minsupplies[g], conffile)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

logger('... sanity checks completed for this configuration.')

# We follow the NUT protocol as if talking to upsd directly.
# 2. For each upsd instance,
#    2a. set up a client socket to talk to upsd/upsdTLS server
#    2b. send STARTTLS to upsd server
#    2c. if STARTTLS OK, install TLS
#    2d. Log into upsd server.
#    2e. Log into UPS units
# 1. Fork to lower privilege,
#    2f. Begin collecting statuses.

# Initialize state dictionaries
for fqups in powerval :
  Dlogger('Initializing raw_status_COMMNOCOMM[{}] and COMMNOCOMM[{}] as \'COMM\''\
          .format(pp_ups(fqups), pp_ups(fqups)))
  raw_status_COMMNOCOMM[fqups] = 'COMM'
  COMMNOCOMM[fqups] = 'COMM'

# 2a. Open a client socket to each upsd server instance identified by domain:port.
# The socket stays open until this client is closed down.
Dlogger ('2a. Checking the {} socket(s) to the upsd instance(s) ...'.format(len(upsd_map)))
for (ups_domain, ups_port) in upsd_map:
  (ups_group, ups_name, certfile) = upsd_map[(ups_domain, ups_port)]
  fqups = fqups_build(ups_domain, ups_port)  # LOCAL:name@localhost:3493

  # Set up fresh socket for this message exchange
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(upsdtimeout)               # Low value speeds up the testing
  try :
    rc = s.connect((ups_domain, int(ups_port)))
    upsd_sock[(ups_domain, ups_port)] = s   # Remember that this upsd uses this socket
  except Exception as ex :
    msg = ('{} Error 1095: Connection to {}:{} refused\n'\
           +tab+'Reason: {}\n'\
           +tab+'Monitor {} expects that the server will be listening at port {}:{}\n'\
           +tab+'before it starts.  Please check that server is running before starting\n'\
           +tab+'the monitor.  Exiting ...')\
           .format(blob, ups_domain, ups_port, ex, prog_name, ups_domain, ups_port)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  logger(('{} Message 1100: Connected to socket {}\n'\
          +tab+'for {}:{} rc={} timeout={}')\
         .format(blob, pp_sock(s),\
                 ups_domain, ups_port, rc, s.gettimeout()))
  Dlogger('2a. Assigning socket {} for {}:{}, timeout = {}'\
           .format(pp_sock(s, long=True), ups_domain, ups_port, s.gettimeout()))

  # 2b. Attempt to start TLS to each upsd
  Dlogger('2b. Attempting to connect to {}:{} ...'.format(ups_domain, ups_port))
  logger('Attempt a STARTTLS to {}:{}'.format(ups_domain, ups_port))
  rc, reply = send_cmd('STARTTLS', ups_domain, ups_port, upsdtimeout)
  m = re.match(r'\s*OK.*',reply)
  m_ERR = re.match(r'.*FEATURE_NOT_CONFIGURED.*',reply)
  if m :                                  # Clear for TLS
    upsd_TLS[(ups_domain,ups_port)] = True
    logger('STARTTLS to {}:{}  Received reply {}'.format(ups_domain, ups_port, reply))
  elif m_ERR :                                  # send_cmd handles COMM->NOCOMM
    upsd_TLS[(ups_domain,ups_port)] = False
    msg = ('{} Warning 1110: STARTTLS to {}:{} not available.\n'\
          +tab+'Response {}\n'\
          +tab+'The logon password for UPS units on this server will be passed in plain text.\n'\
           +tab+'Exiting ...\n')\
          .format(blob, ups_domain, ups_port, reply)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  else :                                  # send_cmd handles COMM->NOCOMM
    upsd_TLS[(ups_domain,ups_port)] = False
    msg = ('{} Error 1120: STARTTLS to {}:{} fails.\n'\
           +tab+'Response {}.  Exiting ...')\
           .format(blob, ups_domain, ups_port, reply)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

  # 2c. Install TLS
  if upsd_TLS[(ups_domain,ups_port)] :
    # Install TLS wrapper for this certificate.
    # openSUSE 42.3 provides antique OpenSSL 1.0.2j-fips 26 Sep 2016
    # so ssl.PROTOCOL_TLS_CLIENT is not available.
    # PROTOCOL_TSLv1_1 is "wrong version". PROTOCOL_SSLv3 is "wrong version number".
    # Testing with ssl.OPENSSL_VERSION = OpenSSL 1.1.1d  10 Sep 2019
    protocol_number = ssl.PROTOCOL_TLS_CLIENT  # Use highest possible, requires Python 3.6
    logger('{} Message 1130: Will use {} ssl.PROTOCOL_TLS_CLIENT = {}'\
           .format(blob, ssl.OPENSSL_VERSION, protocol_number))

    # Get name of protocol from number
    try :              protocol_name = protocol_names[protocol_number]
    except Exception : protocol_name = "unknown"
    Dlogger('2c. Attempting to use ssl protocol number {} name {} ...'\
            .format(protocol_number, protocol_name))

    # Create TLS context
    # C source code useful for debugging the Python error messages is found at
    # https://github.com/python/cpython/blob/3.8/Modules/_ssl.c#L3380-L3460
    try : client_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    except Exception as ex :
      msg = ('{} Error 1140: Unable to create context:\n'\
             +tab+'certfile={}\n'\
             +tab+'Reason: {}\n'\
             +tab+'Exiting ...')\
             .format(blob, certfile, ex)
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
    Dlogger(('2c. TLS client_context = {}\n'\
             +tab+'protocol={}')\
             .format(client_context, protocol_names[client_context.protocol]))
    # We have a context, but are our certificates good enough?
    Dlogger('2c. Attempting to use certificate in certfile = {} ...'\
             .format(certfile))
    try: client_context.load_verify_locations(certfile)
    except Exception as ex :
      # cert_raw_txt = ssl._ssl._test_decode_cert(certfile)   # Human readable, but needs pretty printing
      # pprint.pprint(cert_raw_txt, stream=log, indent=3)
      # https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
      # substrate = pem.readPemFromFile(open('cert.pem'))
      # cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
      msg = ('{} Error 1150: Unable to verify certificate file {}\n'\
             +tab+'Reason: {}\n'\
             +tab+'Exiting ...\n'\
             '{}')\
             .format(blob, certfile, ex, pp_PEM(certfile))
      logger(msg); eprinter(msg)
      cleanup(); exit(1)

    # Turn off timeouts that prevent smooth operation
    # (<class 'socket.timeout'>, timeout('_ssl.c:1091: The handshake operation timed out')
    s.settimeout(None)           # https://github.com/pyca/pyopenssl/issues/168
    try : ss = client_context.wrap_socket(s, server_side=False, server_hostname=ups_domain)
    except ssl.SSLError as ex :
      msg=('{} Error 1160: Unable to install TLS certificate version {} on socket {}.\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...\n'\
           '{}')\
           .format(blob, ssl.OPENSSL_VERSION, pp_sock(s), ex, pp_PEM(certfile))
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
    except Exception as ex :
      msg=('{} Error 1165: Unable to install TLS certificate version {} on socket {}\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...\n'\
           '{}')\
           .format(blob, ssl.OPENSSL_VERSION, pp_sock(s), ex, pp_PEM(certfile))
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
    logger(('Installed TLS wrapper version {}\n'\
            +tab+'on TLS socket {} for {} with client certificate {}\n'\
            '{}')\
           .format(ssl.OPENSSL_VERSION, pp_sock(ss), ups_domain, certfile, pp_PEM(certfile)))
    ss.settimeout(upsdtimeout)            # Workaround for socket.timeout

#    # Let's see the server certificate
#    try : server_cert = ss.getpeercert()
#    except : server_cert = "getpeercert failed"
#    logger(('Socket {} peer certificate:\n'\
#            '{}')\
#            .format(pp_sock(ss), pp_PEM(server_cert)))
    # Which TLS protocol is used ?
    prot_in_use = ss.version()
    logger('Socket {} to {}:{} uses TLS version {}'\
           .format(pp_sock(ss), ups_domain, ups_port, prot_in_use))

    # Update upsd_map with new socket
    upsd_sock[(ups_domain, ups_port)] = ss   # Remember that this upsd uses this socket
    Dlogger('2c. upsd_sock[({}, {})] replaced by {}'\
            .format(ups_domain, ups_port, pp_sock(ss)))

  # 2d. Log in to upsd, expect OK
  # The nut protocol identifies a user by the data given in file upsd.users :
  # each user is identified by name and password.
  rc, reply = send_cmd('USERNAME ' + upsduser[fqups], ups_domain, ups_port, upsdtimeout)
  m = re.match(r'\s*OK.*',reply)
  if m :
    Dlogger('2d. upsd server {}:{} accepts USERNAME {}'\
           .format(ups_domain, ups_port, upsduser[fqups]))
  else :
    msg=('{} Error 1170: USERNAME {} rejected for upsd server {}:{}.\n'\
         +tab+'Exiting ...')\
         .format(blob, upsduser[fqups], ups_domain, ups_port)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  rc, reply = send_cmd('PASSWORD ' + password[fqups], ups_domain, ups_port, upsdtimeout)
  m = re.match(r'\s*OK.*',reply)
  if m :
    Dlogger('2d upsd server {}:{} accepts PASSWORD'\
            .format(ups_domain, ups_port, password[fqups]))
  else :
    msg=('{} Error 1180: Password failed for upsd server {}:{}.\n'\
         +tab+'Exiting ...')\
        .format(blob, upsduser[fqups], ups_domain, ups_port)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
# End of for (ups_domain, ups_port) in upsd_map:

count_TLS = len([upsd_TLS[u] for u in upsd_TLS if upsd_TLS[u]])
count_not_TLS = len(upsd_TLS) - count_TLS
logger ('... {} socket(s) opened. TLS protected: {}, not protected: {}'\
        .format(len(upsd_TLS), count_TLS, count_not_TLS))

# 2e. Attach the UPS units
# upsd keps a count the secondaries protected by a given UPS. 
# We now add our UPS units to this count.
# Note that since primaries are also counted, the count is 1 + number of secondaries.
for fqups in powerval :
  if powerval[fqups] == 0 :
    Dlogger('2e. Not counting {} since powerval = 0'.format(pp_ups(fqups)))
    continue
  Dlogger('2e. Counting {} fed by UPS {} ...'.format(mastslav[fqups], pp_ups(fqups)))
  m = re.match(re_fqups,fqups)
  if not m :
    msg=('{} Error 1190: Internal error: Unable to decode fqups {}.\n'\
        +tab+'Exiting ...').format(blob, fqups)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
  if (ups_domain, ups_port) in upsd_sock :
    s = upsd_sock[(ups_domain, ups_port)]
    Dlogger('2e. upsd_sock[({}, {})] = {}'.format(ups_domain, ups_port, pp_sock(s)))
    rc, reply = send_cmd('LOGIN ' + ups_name, ups_domain, ups_port, upsdtimeout)
    m_ok = re.match(r'\s*OK.*',reply)
    m_ali = re.match(r'\s*ERR\s*ALREADY-LOGGED-IN.*',reply)
    if m_ok :
      Dlogger('... counted {} fed by UPS {}'.format(mastslav[fqups], pp_ups(fqups)))
    elif m_ali :                          # Two UPS units share an administrator.
      msg=('{} Warning 1200: LOGIN {} for UPS {}\n'\
           +tab+'upsd replied: {}   Continuing ...')\
           .format(blob, ups_name, pp_ups(fqups), reply)
      logger(msg); eprinter(msg)
    else :
      msg=('{} Error 1210: LOGIN {} fails for UPS {}\n'\
           +tab+'upsd replied: {}'\
           +tab+'Exiting ...')\
           .format(blob, ups_name, pp_ups(fqups), reply)
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
  else :
    msg=('{} Error 1220: LOGIN to {}:{} has no socket.\n'\
         +tab+'Exiting ...')\
         .format(blob, ups_domain, ups_port)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)

  # If required, claim to be primary, falling back on master
  if mastslav[fqups] == 'master' :
    Dlogger('2e. Claiming to be the primary of UPS {} ...'.format(pp_ups(fqups)))
    rc, reply = send_cmd('PRIMARY ' + ups_name, ups_domain, ups_port, upsdtimeout)
    m = re.match(r'\s*OK.*',reply)
    if m :
      Dlogger('... claimed to be primary of UPS {}'.format(pp_ups(fqups)))
    else :
      Dlogger('2e. Claiming to be the master of UPS {} ...'.format(pp_ups(fqups)))
      rc, reply = send_cmd('MASTER ' + ups_name, ups_domain, ups_port, upsdtimeout)
      m = re.match(r'\s*OK.*',reply)
      if m :
        Dlogger('... claimed mastery of UPS {}'.format(pp_ups(fqups)))
      else :
        msg=('{} Error 1230: PRIMARY and MASTER requests refused for {}.\n'\
             +tab+'Exiting ...')\
             .format(blob, pp_ups(fqups))
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
# End of for fqups in powerval :
# End of 2e. log into UPS units

#############################################################################################
# The forking is held back until we are sure that we can access the UPS units
# and log into them.  All the UPS should have status COMM for a clean start.
# 1. Fork and move to lower privilege
if fork :
  logger('Prepare to fork and move to lower privilege ...')
  Dlogger(('calling_user = {}, run_as_user = {}.')\
          .format(calling_user, run_as_user))
  # Yes, we fork and daemonize
  msg = ('{} Process {} forking ...')\
         .format(fnl(), os.getpid())
  logger(msg); eprinter(msg)
  # Fork a copy of the root process to create a "run_as_user" process
  # This creates a complete copy including the messages destined for NUTLOG.
  try : child_pid = os.fork ()               # Create copy of self.  Child will drop privilege
  except Exception as ex :
    msg=('{} Error 1000: Error when forking:\n'\
         +tab+'Reason: {}\n'
         +tab+'Exiting ...')\
         .format(blob, ex)
    logger(msg); eprinter(msg)
    cleanup() ; exit (1)
  if child_pid > 0 :                         # Parent process receives child's PID
    # Write child's PID to file for systemd to enjoy.
    logger('{} Message 1004: Writing child PID {} to file {}'\
           .format(blob, child_pid, PIDfile))
    try :
      with open(PIDfile, 'wt') as PID_fd :
        PID_fd.write('{}'.format(child_pid))   # write likes strings, not integers
        PID_fd.close()
    except Exception as ex :
      msg=('{} Error 1005: Unable to create PID file {}\n'\
           +tab+'Reason: {}\n'
           +tab+'Exiting ...')\
           .format(blob, PIDfile, ex)
      logger(msg); eprinter(msg)
      cleanup() ; exit (1)
    msg = ('{} Message 1010: Parent says: child {} forked ...\n'\
           +tab+'Child\'s messages are in log file {}\n'\
           +tab+'Parent process {} does not wait for child\'s daemon process {}.\n'\
           +tab+"Hint: to stop a working daemon, type command 'killall -SIGTERM {}'\n"\
           +tab+"To stop a broken daemon, type command 'killall -SIGKILL {}'\n"\
           +tab+'Parent now exits.  Adieu.')\
           .format(blob, child_pid, log_file, os.getpid(), child_pid, prog_name, prog_name)
    logger(msg); eprinter(msg)
    # Parent exits, child is inherited by init.  Child does cleanup
    exit (0)

  # Child process still attached to TTY
  time.sleep(0.5)                            # Wait for parent to exit
  msg = ('{} Message 1020: Child says: I am forked process {}, my honorable parent is process {}.\n'\
         +tab+'孝, xiào: La piété filiale est la première virtue. Filial piety is the first virtue.')\
         .format(blob, os.getpid(), os.getppid())
  logger(msg)
  # Daemonization: Child changes user: run_as_user could be ('upsd', 'x', 478, 2)
  msg = '{} Message 1030: Child changing to user "{}", UID {}, GID {} ...'\
        .format(blob, run_as_user[0], run_as_user[2], run_as_user[3])
  logger(msg)
  os.setgid(run_as_user[3])
  os.setuid(run_as_user[2])
  PID = os.getpid(); UID = os.getuid(); GID = os.getgid(); PPID = os.getppid()
  logger('{} Message 1040: Child changed user: {}@{}  PID: {}, UID = {}, GID = {}.'\
         .format(blob, run_as_user[0], hostname, PID, UID, GID))

  # Child changes current working directory
  home_dir = pwd.getpwuid(os.getuid()).pw_dir  # run_as_user's working directory
  try :              os.chdir(home_dir)        # Anticipate working directory problem
  except Exception : os.chdir('/')
  logger("{} Message 1050: Child changed current working directory to {}"\
         .format(blob, os.getcwd()))
  umask = 0o007   # World + dog not able to see or modify files created by daemon
  os.umask(umask)
  logger(("{} Message 1060: Child changed umask to octal %3.3o" % os.umask(umask))\
          .format(blob))
  # Child changes session ID, looses TTY
  os.setsid(); SID = os.getsid(PID)
  logger("{} Message 1070: Child PID = {}, PPID = {}, changes SID to {}"\
         .format(blob, PID, PPID, SID))
  # Continue the daemonisation by re-directing stdout and stderr
  # If needed, restore using sys.stdout = sys.__stdout__
  msg = ('{} Message 1080: Child redirecting Python\'s stdout and stderr to log file {} ...\n'\
        +tab+'Actions PRINT and EPRINT closing.  Hint: Use NUTLOG.')\
        .format(blob, log_file)
  logger(msg)
  stderr_redirect = True                       # Cleanup needs to know about this redirect
  sys.stdout = log                             # Assume permissions ok
#  sys.stdout.seek(0,2)                        # Child appends to 0th byte at end of file
  sys.stderr = log

  #  os.system('ps -elf | grep "net-mgr.py"')
  #  os.system('ps -elf | grep -E "nut[dms]|UPSmon"')
  #  os.system('netstat -an | grep "3493 "')
  #  os.system('lsof -i :nut -n +c 10')
  # Check that we really have changed user.
  DDlogger('Verify that current user {} has required UID {}...'\
           .format(run_as_user[0], run_as_user[2]))
  if run_as_user[2] != os.getuid() :
    msg = '{} Error 1090: Child failed to change to user {}, UID is {}, not {}'\
          .format(blob, run_as_user[0], os.getuid(), run_as_user[2])
    logger(msg); eprinter(msg)

else : logger('No forking this time.')

# The following code is executed by the run_as_user daemon or by the original caller.

start_timer(('start', 1))                 # TIMEOUT start when UPSmon.py starts

#    DDcommand('netstat -an | grep "3493 "')
#    DDcommand('lsof -i :nut -n +c 10')

#############################################################################################
#    2f. Begin collecting statuses.
# We now have a socket for each UPS unit and we are logged in
# Prepare for loop every POLLFREQ seconds
# Loop forever waiting for status changes from upsd, timeouts and signals
while not SIG_called['TERM'] :     # Loop will be broken if Stop set to True
  poll_number += 1
  time_at_loop_start = time.time()
  newday = datetime.date.today().isoformat()
  if newday == today : pass
  else :
    today = newday
    line = '{} {} {} {} {}'.format(today, '#'*34, 'loop_forever', poll_number, '#'*34)
    logger(line)
  Dlogger ('ddd {} {}'.format(poll_number, '#'*34))
  # Attempt to reload configuration if SIGHUP or newer configuration file available
  if SIG_called['HUP'] :
    msg = 'SIGHUP called.  For the moment, no configuration file reload.'
    print(msg); logger(msg)
  DDlogger('Timer list = {}'.format(active_timers))

  # Poll the UPS units for their status and any timeouts
  for fqups in powerval :
    Dlogger('Polling {} ...'.format(pp_ups(fqups)))
    m = re.match(re_fqups,fqups)
    if not m :
      msg=("{} Error 1240: Internal error: Unable to decode fqups {}.\n"\
          +tab+"Exiting ...").format(blob, fqups)
      logger(msg); eprinter(msg)
      cleanup(); exit(1)
    ups_group, ups_name, ups_domain, ups_port = fqups_explode(fqups)
    s = upsd_sock[(ups_domain, ups_port)]

    # Get this UPS unit's new status list from upsd's ups.status
    rc, reply = send_cmd('GET VAR {} ups.status'.format(ups_name), ups_domain, ups_port, upsdtimeout)
    Dlogger('ddd {} GET VAR {} ups.status: rc=«{}»   reply=«{}»'.format(poll_number, ups_name, rc, reply))
    # Typically reply=«VAR Eaton ups.status "OL"»
    if reply != 'NOCOMM' :            # upsd is COMM for this fqups
      # Merge the raw statuses read from upsd and the timeouts
      Dlogger('ddd {} raw_status_list_TO = {}'.format(poll_number, raw_status_list_TO))
      raw_status_list = re.split('[\s\"]',reply) + raw_status_list_TO # pylint: disable=anomalous-backslash-in-string
      Dlogger('ddd {} raw_status_list = {}'.format(poll_number, raw_status_list))
      new_status_list=[st for st in raw_status_list[4:] if not st == '']
      Dlogger('ddd {} new_status_list = {}'.format(poll_number, new_status_list))
    else :                          # upsd is NOCOMM for this fqups
      new_status_list = raw_status_list_TO
    # Transfer of status changes from raw_status_COMMNOCOMM to raw_status_list
    new_status_list.append(raw_status_COMMNOCOMM[fqups])   # Append the COMM/NOCOMM status

    # Look for battery.charge.low.i events
    charge[fqups] = get_battery_charge(fqups)    # E.g. integer 42, or 999 if no data
    status = {1:'LB1', 2:'LB2', 3:'LB3'}
    for i in battery_charge_low[fqups] :
      if charge[fqups] <= battery_charge_low[fqups][i] : new_status_list.append(status[i])
    Dlogger('ddd {} new_status_list = {}  active_timers = {}'\
            .format(poll_number, new_status_list, pp_active_timers(active_timers)))

    # Look for minsupplies not satisfied events
    # In the group to which this UPS belongs, do we have enough "powervalues" to cover the minsupplies ?
    # Did the user blow off a foot as predicted by 2.7.4 upsmon.c 1812 ?
    # During the first polling loop, OLOB is not yet initialised
    if poll_number < 2 : pass
    else :
      current_power = 0
      for u in group_fqups[ups_group] :     # All the UPS units in this group
        if OLOB[u] == 'OB' : pass
        else : current_power += int(powerval[u])
      if current_power < int(minsupplies[ups_group]) :
        new_status_list.append('LS')        # Append LS status
        Dlogger(('Not enough power supplies in group {}.  Required {}, available {}.\n'\
                 +tab+'UPS {} now in state LS. new_status_list = {}')
                 .format(ups_group, minsupplies[ups_group], current_power, pp_ups(u), new_status_list))

    # Do we have an event for this UPS, i.e. a status change ?
    for new_status in new_status_list :
      # Try each possible upsd status in turn.   Extract timer name from 'TO(name)'
      mTO = re.match('TO\(([^\)]+)\)',new_status) # pylint: disable=anomalous-backslash-in-string
      Dlogger('ddd {} new_status = {}   mTO={} timer name?'.format(poll_number, new_status, mTO))
      if   safe_get('ALARMNone',fqups) == new_status : continue          # No status change
      elif safe_get('BOOSTNone',fqups) == new_status : continue          # No status change
      elif safe_get('BYPASSNone',fqups) == new_status : continue         # No status change
      elif safe_get('CALNone',fqups) == new_status : continue            # No status change
      elif safe_get('CHRGNone',fqups) == new_status : continue           # No status change
      elif safe_get('DISCHRGNone',fqups) == new_status : continue        # No status change
      elif safe_get('FSDNone',fqups) == new_status : continue            # No status change
      elif safe_get('LBNone',fqups) == new_status : continue             # No status change
      elif safe_get('LB1None',fqups) == new_status : continue            # No status change
      elif safe_get('LB2None',fqups) == new_status : continue            # No status change
      elif safe_get('LB3None',fqups) == new_status : continue            # No status change
      elif safe_get('LSNone',fqups) == new_status : continue             # No status change
      elif safe_get('COMMNOCOMM',fqups,'COMM') == new_status : continue  # No status change
      elif safe_get('OFFNone',fqups) == new_status : continue            # No status change
      elif safe_get('OLOB',fqups,'OL') == new_status : continue          # No status change
      elif safe_get('OVERNone',fqups) == new_status : continue           # No status change
      elif safe_get('RBNone',fqups) == new_status : continue             # No status change
      elif safe_get('TESTNone',fqups) == new_status : continue           # No status change
      elif safe_get('TRIMNone',fqups) == new_status : continue           # No status change
      elif safe_get('TICKNone',fqups) == new_status : continue           # No status change
      elif safe_get('TOCKNone',fqups) == new_status : continue           # No status change
      elif (safe_get('ALARMNone',fqups) == None) and (new_status == 'ALARM') :
        event = (None,'ALARM');       ALARMNone[fqups] = 'ALARM';     do_action (fqups,event)
      elif (safe_get('BOOSTNone',fqups) == None) and (new_status == 'BOOST') :
        event = (None,'BOOST');       BOOSTNone[fqups] = 'BOOST';     do_action (fqups,event)
      elif (safe_get('BYPASSNone',fqups) == None) and (new_status == 'BYPASS') :
        event = (None,'BYPASS');      BYPASSNone[fqups] = 'BYPASS';   do_action (fqups,event)
      elif (safe_get('CALNone',fqups) == None) and (new_status == 'CAL') :
        event = (None,'CAL');         CALNone[fqups] = 'CAL';         do_action (fqups,event)
      elif (safe_get('CHRGNone',fqups) == None) and (new_status == 'CHRG') :
        event = (None,'CHRG');        CHRGNone[fqups] = 'CHRG';       do_action (fqups,event)
      elif (safe_get('DISCHRGNone',fqups) == None) and (new_status == 'DISCHRG') :
        event = (None,'DISCHRG');     DISCHRGNone[fqups] = 'DISCHRG'; do_action (fqups,event)
      elif (safe_get('FSDNone',fqups) == None) and (new_status == 'FSD') :
        event = (None,'FSD');         FSDNone[fqups] = 'FSD';         do_action (fqups,event)
      elif (safe_get('LBNone',fqups) == None) and (new_status == 'LB') :
        event = (None,'LB');          LBNone[fqups] = 'LB';           do_action (fqups,event)
      elif (safe_get('LB1None',fqups) == None) and (new_status == 'LB1') :
        event = (None,'LB1');         LB1None[fqups] = 'LB1';         do_action (fqups,event)
      elif (safe_get('LB2None',fqups) == None) and (new_status == 'LB2') :
        event = (None,'LB2');         LB2None[fqups] = 'LB2';         do_action (fqups,event)
      elif (safe_get('LB3None',fqups) == None) and (new_status == 'LB3') :
        event = (None,'LB3');         LB3None[fqups] = 'LB3';         do_action (fqups,event)
      elif (safe_get('LSNone',fqups) == None) and (new_status == 'LS') :
        event = (None,'LS');          LSNone[fqups] = 'LS';           do_action (fqups,event)
      elif (safe_get('COMMNOCOMM',fqups,'COMM') == 'COMM') and (new_status == 'NOCOMM') :
        event = ('COMM','NOCOMM');    COMMNOCOMM[fqups] = 'NOCOMM';   do_action (fqups,event)
      elif (safe_get('COMMNOCOMM',fqups,'COMM') == 'NOCOMM') and (new_status == 'COMM') :
        event = ('NOCOMM','COMM');    COMMNOCOMM[fqups] = 'COMM';     do_action (fqups,event)
      elif (safe_get('OFFNone',fqups) == None) and (new_status == 'OFF') :
        event = (None,'OFF');         OFFNone[fqups] = 'OFF';         do_action (fqups,event)
      elif (safe_get('OLOB',fqups,'OL') == 'OB') and (new_status == 'OL') :
        event = ('OB','OL');          OLOB[fqups] = 'OL';             do_action (fqups,event)
      elif (safe_get('OLOB',fqups,'OL') == 'OL') and (new_status == 'OB') :
        event = ('OL','OB');          OLOB[fqups] = 'OB';             do_action (fqups,event)
      elif (safe_get('OVERNone',fqups) == None) and (new_status == 'OVER') :
        event = (None,'OVER');        OVERNone[fqups] = 'OVER';       do_action (fqups,event)
      elif (safe_get('RBNone',fqups) == None) and (new_status == 'RB') :
        event = (None,'RB');          RBNone[fqups] = 'RB';           do_action (fqups,event)
      elif (safe_get('TESTNone',fqups) == None) and (new_status == 'TEST') :
        event = (None,'TEST');        TESTNone[fqups] = 'TEST';       do_action (fqups,event)
      elif (safe_get('TRIMNone',fqups) == None) and (new_status == 'TRIM') :
        event = (None,'TRIM');        TRIMNone[fqups] = 'TRIM';       do_action (fqups,event)
      elif (safe_get('TICKNone',fqups) == None) and (new_status == 'TICK') :
        event = (None,'TICK');        TICKNone[fqups] = 'TICK';       do_action (fqups,event)
      elif (safe_get('TOCKNone',fqups) == None) and (new_status == 'TOCK') :
        event = (None,'TOCK');        TOCKNone[fqups] = 'TOCK';       do_action (fqups,event)
      elif mTO :
        event = ('TO',mTO.group(1))
        raw_status_list_TO.remove(new_status) ;                       do_action (fqups,event)
      else :
        msg = ('{} Error 1250: loop_forever: Internal error: ups = {}\n'\
               +tab+'for new_status = {} in new_status_list {}\n'\
               +tab+'Status change falls through.\n'\
               +tab+'There is no test for status {},\n'\
               +tab+'or no directory corresponding to safe_get(<directory>,fqups)')\
               .format(blob, pp_ups(fqups), new_status, new_status_list, new_status)
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
    DDlogger('GET VAR {} new_status_list = {} Looking for X->None'.format(ups_name, new_status_list))
    if   (safe_get('ALARMNone',fqups) == 'ALARM') and ('ALARM' not in new_status_list) :
      event = ('ALARM',None);       ALARMNone[fqups] = None;        do_action (fqups,event)
    elif (safe_get('BOOSTNone',fqups) == 'BOOST') and ('BOOST' not in new_status_list) :
      event = ('BOOST',None);       BOOSTNone[fqups] = None;        do_action (fqups,event)
    elif (safe_get('BYPASSNone',fqups) == 'BYPASS') and ('BYPASS' not in new_status_list) :
      event = ('BYPASS',None);      BYPASSNone[fqups] = None;       do_action (fqups,event)
    elif (safe_get('CALNone',fqups) == 'CAL') and ('CAL' not in new_status_list) :
      event = ('CAL',None);         CALNone[fqups] = None;          do_action (fqups,event)
    elif (safe_get('CHRGNone',fqups) == 'CHRG') and ('CHRG' not in new_status_list) :
      event = ('CHRG',None);        CHRGNone[fqups] = None;         do_action (fqups,event)
    elif (safe_get('DISCHRGNone',fqups) == 'DISCHRG') and ('DISCHRG' not in new_status_list) :
      event = ('DISCHRG',None);     DISCHRGNone[fqups] = None;      do_action (fqups,event)
    elif (safe_get('FSDNone',fqups) == 'FSD') and ('FSD' not in new_status_list) :
      event = ('FSD',None);         FSDNone[fqups] = None;          do_action (fqups,event)
    elif (safe_get('LBNone',fqups)  == 'LB') and ('LB' not in new_status_list) :
      event = ('LB',None);          LBNone[fqups] = None;           do_action (fqups,event)
    elif (safe_get('LB1None',fqups) == 'LB1') and ('LB1' not in new_status_list) :
      event = ('LB1',None);         LB1None[fqups] = None;          do_action (fqups,event)
    elif (safe_get('LB2None',fqups) == 'LB2') and ('LB2' not in new_status_list) :
      event = ('LB2',None);         LB2None[fqups] = None;          do_action (fqups,event)
    elif (safe_get('LB3None',fqups) == 'LB3') and ('LB3' not in new_status_list) :
      event = ('LB3',None);         LB3None[fqups] = None;          do_action (fqups,event)
    elif (safe_get('LSNone',fqups)  == 'LS') and ('LS' not in new_status_list) :
      event = ('LS',None);          LSNone[fqups] = None;           do_action (fqups,event)
    elif (safe_get('OFFNone',fqups) == 'OFF') and ('OFF' not in new_status_list) :
      event = ('OFF',None);         OFFNone[fqups] = None;          do_action (fqups,event)
    elif (safe_get('OVERNone',fqups) == 'OVER') and ('OVER' not in new_status_list) :
      event = ('OVER',None);        OVERNone[fqups] = None;         do_action (fqups,event)
    elif (safe_get('RBNone',fqups) == 'RB') and ('RB' not in new_status_list) :
      event = ('RB',None);          RBNone[fqups] = None;           do_action (fqups,event)
    elif (safe_get('TESTNone',fqups) == 'TEST') and ('TEST' not in new_status_list) :
      event = ('TEST',None);        TESTNone[fqups] = None;         do_action (fqups,event)
    elif (safe_get('TRIMNone',fqups) == 'TRIM') and ('TRIM' not in new_status_list) :
      event = ('TRIM',None);        TRIMNone[fqups] = None;         do_action (fqups,event)
    elif (safe_get('TICKNone',fqups) == 'TICK') and ('TICK' not in new_status_list) :
      event = ('TICK',None);        TICKNone[fqups] = None;         do_action (fqups,event)
    elif (safe_get('TOCKNone',fqups) == 'TOCK') and ('TOCK' not in new_status_list) :
      event = ('TOCK',None);        TOCKNone[fqups] = None;         do_action (fqups,event)

  # Pause before looping.  Are there any alert conditions in OLOB or LBNone?
  period = pollfreq                       # When nothing is happening
  for ups in OLOB :
    if OLOB[ups] == 'OB' : period = pollfreqalert
  for ups in LBNone :
    if LBNone[ups] == 'LB' : period = pollfreqalert
  time_at_loop_end = time.time()
  loop_process_time = time_at_loop_end - time_at_loop_start  # Hopefully less than the period
  wait_time = max(period - loop_process_time, 0)
  DDlogger('End of loop processing which has taken {:.3f}s, period = {}s, will wait {:.3f}s.'\
           .format(loop_process_time, period, wait_time))
  try :
    time.sleep(float(wait_time))          # Float required?
  except KeyboardInterrupt as err :
    msg = "{} Message 1260: Interrupted by keyboard action.  Exiting ..."\
          .format(blob)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  except Exception as ex :
    msg = ('{} Message 1277: Interrupted:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...')\
           .format(blob, ex)
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  continue
  # End of for fqups in powerval

# End of while not SIG_called['TERM']

# Cleanup on final exit
Dstate_logger()                           # Log state globals if -D called
cleanup()
exit(rc)
# Adieu
