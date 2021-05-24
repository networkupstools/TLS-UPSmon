#!/usr/bin/python3 -u
# mkUPSmonconf Make a configuration file for UPSmon.py
# Copyright (C) 2020 Roger Price. GPL v3 or later at your choice.
# 2020-09-19 Version 1.0
'''mkUPSmonconf: Make a configuration file for UPSmon.py'''
mkUPSmonconf_version='1.1'

# Changes:
# 2020-10-26 RP Added builtin timer 'start'
# 2020-11-05 RP Defalt port becomes IANA ups/401
# 2020-11-17 RP Actions for battery.charge.low.i, statuses LBi
# 2020-11-27 RP OS ID improvement
# 2021-05-11 RP monitor -> client

# We need some library stuff
import argparse, datetime, os, re, sys, subprocess

if sys.version_info[0] >= 3 and sys.version_info[1] >= 4 : pass
else :
  msg='\tMessage 50: This program requires Python version 3.4 or later.\n'\
      '\tYou are using version {}.'\
      .format(sys.version.replace('\n',''))
  print(msg, file=sys.stderr, flush=True)
  exit(1)

#############################################################################################
#                                   Functions
#############################################################################################
#############################################################################################
# Function do_command takes a command and its options in a list of strings,
# and returns stdout, stderr as iterable list of lines of utf-8 text.
# The command may be specified as a list of strings or as a single string.
# E.g. stdout, stderr = do_command(['/bin/bash', '-s', 'ls', '-alF'])
#      stdout, stderr = do_command('ls -l .'])
#      if not stdout == None :
#        for line in stdout :
# If error, displays message before returning stdout and stderr.
# It would be better to use shlex.split(command_line_string)
def do_command (L, use_shell=False) :
  try :
    # Execute the command
    RC = subprocess.Popen(L, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=use_shell)
    bstdout, bstderr = RC.communicate()
    if bstdout == None : stdout = None
    else : stdout = re.split('\n',bstdout.decode("utf-8"))     # Convert bytes to iterable lines of text
    if bstderr == None : stderr = None
    # Convert bytes to iterable lines of text and remove '' elements from list
    else : stderr = [x for x in re.split('\n',bstderr.decode("utf-8")) if x != '']
    # Handle error output from command
    if stderr != [] :
      msg = (('Error 585: do_command receives error message when calling\n'\
              '\t {}\n'\
              '\t stderr = {}\n'\
              '\t Continuing ...')\
             .format(string_list_to_string(L), stderr))
      print(msg, file=sys.stderr, flush=True)
    return stdout, stderr                 # Official exit from this function
  # Subprocess problems
  except Execption as ex :
    msg = ('Error 590: do_command error: Unable to execute command\n'\
           '\t {}\n'\
           '\t Reason: {}\n'\
           '\t Continuing ...')\
           .format(L, ex)
    print(msg, file=sys.stderr, flush=True)
    return None, None

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
          if m : return m.group(1).follow() # E.g. debian
        return None                       # No ID in os-release
    except Exception :
      try :
        with open('/etc/gentoo-release', 'r') as fd :
          return 'gentoo'
      except Exception : return None      # No *-release
  msg = ('Error 620: get_OS_id error: I do not recognize uname result {}\n'\
         '\t Continuing ...').format(stdout_list[0])
  print(msg, file=sys.stderr, flush=True)
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
#                                   Main program
#############################################################################################
# Assume that this program is being run in the system running upsd.
# Who are we ?
try : hostname = socket.gethostname()     # PEP 8 look away
except Exception : hostname = 'upsd'

# Try to guess where things go in this system
default_user, etc_dir = get_NUT_install_params()

argparser = argparse.ArgumentParser(
  description='mkUPSmonconf.py is a Python3 script to build a configuration'
              '  file UPSmon.conf for UPSmon.py.  Output is to STDOUT.'
              '  Status: "experimental".  Intended for demonstration and experiment.',
  epilog='License: GPL v3 or later at your choice.\n'
         'Support: nut-upsuser mailing list.\n'
         'Documentation: http://rogerprice.org/NUT/ConfigExamples.A5.pdf')
argparser.add_argument('--plan',          nargs=1, choices=['standard','timed'],
                       help='Specify standard or timed shutdown plan. Valid options are %(choices)s.',
                       metavar='standard|timed')
argparser.add_argument('--ups',           nargs=1,
                       help='The name of your UPS, for example UPS_123',
                       metavar='<name>')
argparser.add_argument('--upsdname',      nargs=1,
                       help='Name of the system on which upsd runs. E.g. localhost',
                       metavar='<name>')
argparser.add_argument('--upsdport',      nargs=1,
                       help='TLS port used by upsd/upsdTLS.py. E.g. 401',
                       metavar='<integer>')
argparser.add_argument('--clientcertfile',      nargs=1,
                       help='File which holds the public TLS certificate needd to access upsd.'\
                            ' E.g. '+etc_dir+'bigbox-client.cert.pem',
                       metavar='<filename>')
argparser.add_argument('--upsduser',      nargs=1,
                       help='User for this UPS, as given in upsd.users. E.g. [leboss]',
                       metavar='<name>')
argparser.add_argument('--upsdpass',      nargs=1,
                       help='Password for the upsd user, as given in upsd.users.',
                       metavar='<string>')
argparser.add_argument('--smtpserver',    nargs=1,
                       help='Your e-mail server. E.g. mailbox.mailserver.com',
                       metavar='<domain>')
argparser.add_argument('--smtpport',      nargs=1,
                       help='Your e-mail server TLS port. E.g. 465',
                       metavar='<integer>')
argparser.add_argument('--smtpuser',      nargs=1,
                       help='Your account name on the e-mail server. E.g. mailbox@mydomain.com',
                       metavar='<name>')
argparser.add_argument('--smtppass',      nargs=1,
                       help='The password for your account name on the e-mail server. E.g. qwertyuiop',
                       metavar='<string>')
argparser.add_argument('--emailfrom',     nargs=1,
                       help='Email address from which messages will be sent. E.g. "<bigserver@bigU.edu>"',
                       metavar='<string>')
argparser.add_argument('--emailto',       nargs=1,
                       help='Email address to which messages will be sent. E.g. "Big Joe <jschmoe@bigU.edu>"',
                       metavar='<string>')
argparser.add_argument('-v', '--version', action='version',
                       help='Show program and Python versions, then exit.',
                       version='%(prog)s {} running on Python {}'
                       .format(mkUPSmonconf_version, sys.version.replace('\n','')))
args = argparser.parse_args()

e = False
if args.plan is None :          print('You have forgotten to specify option --plan') ; e = True
if args.ups is None :           print('You have forgotten to specify option --ups') ; e = True
if args.upsdname is None :      print('You have forgotten to specify option --upsdname') ; e = True
if args.upsdport== None :       print('You have forgotten to specify option --upsdport') ; e = True
if args.clientcertfile== None : print('You have forgotten to specify option --clientcertfile') ; e = True
if args.upsduser is None :      print('You have forgotten to specify option --upsduser') ; e = True
if args.upsdpass is None :      print('You have forgotten to specify option --upsdpass') ; e = True
if args.smtpserver is None :    print('You have forgotten to specify option --smtpserver') ; e = True
if args.smtpport is None :      print('You have forgotten to specify option --smtpport') ; e = True
if args.smtpuser is None :      print('You have forgotten to specify option --smtpuser') ; e = True
if args.smtppass is None :      print('You have forgotten to specify option --smtppass') ; e = True
if args.emailfrom is None :     print('You have forgotten to specify option --emailfrom') ; e = True
if args.emailto is None :       print('You have forgotten to specify option --emailto') ; e = True
if e :
  print('type mkUPSmonconf --help for help.')
  exit()

conf = []
conf.append('# UPSmon.conf {} shutdown plan generated by mkUPSmonconf.py version {} on {}'\
            .format(args.plan[0], mkUPSmonconf_version, datetime.datetime.now().isoformat()))
conf.append('# Python version {} running on {}'\
            .format(sys.version.replace('\n',' '), os.uname().nodename))
line='# Calling command:'                   # Build up display of user's parameters
for x in sys.argv: line = line + " {}".format(str(x))
conf.append(line)
conf.append('# Support: nut-upsuser mailing list.')
conf.append('# Documentation: http://rogerprice.org/NUT/ConfigExamples.A5.pdf')
conf.append('')
conf.append('# All groups share the same POLLFREQ and POLLFREQALERT and e-mail relay')
conf.append('POLLFREQ 5.0  POLLFREQALERT 5.0')
conf.append('SMTPSERVER [SMTPSERVER] PORT [SMTPPORT] USER [SMTPUSER] PASSWORD [SMTPPASS]')
conf.append('')
conf.append('# Named messages  Let hostname = hostname is built in.')
conf.append('LET banner        = ⸢[%(b)s] UPS=%(u)s charge=%(c)s event=%(e)s⸥')
conf.append('LET Msg-COMM      = banner " I have re-established communication with this UPS."')
conf.append('LET Msg-NOCOMM    = banner " I have lost communication with this UPS."')
conf.append('LET Msg-OL        = banner " Power restored, shutdown cancelled."')
conf.append('LET Msg-RB        = banner " Battery needs replacement."')
conf.append('LET Msg-shutdown  = banner " On battery, shutting down now ..."')
conf.append('LET Certfile      = [CERTFILE]')
conf.append('')
conf.append('##############################################################################')
conf.append('# The local UPS units')
conf.append('GROUP LOCAL HOST [UPSDNAME] PORT [UPSDPORT] CERTFILE Certfile')
conf.append('MONITOR [UPS] POWERVAL 1 UPSDUSER [UPSDUSER] PASSWORD [UPSDPASS] TYPE master')
conf.append('MINSUPPLIES 1')
conf.append('')
if args.plan[0] == 'timed' :
  conf.append('# Timed plan specific actions')
  conf.append('LET Msg-2-min = banner " On battery, possible shutdown in 2 mins, save your work ..."')
  conf.append('LET Msg-1-min = banner " On battery, probable shutdown in 1 min, save your work ..."')
  conf.append('WHEN [UPS] REPORTS OL->OB :   NOTIFY Msg-2-min NUTLOG Msg-2-min WALL Msg-2-min')
  conf.append('                              STARTTIMER two-min 120 STARTTIMER one-min 60')
  conf.append('WHEN [UPS] TIMEOUT one-min :  NOTIFY Msg-1-min NUTLOG Msg-1-min WALL Msg-1-min')
  conf.append('WHEN [UPS] TIMEOUT two-min :  NOTIFY Msg-shutdown NUTLOG Msg-shutdown WALL Msg-shutdown')
  conf.append('                              STARTTIMER final-delay 5')
  conf.append('WHEN [UPS] REPORTS OB->OL :   NOTIFY Msg-OL NUTLOG Msg-OL WALL Msg-OL')
  conf.append('                              CANCELTIMER two-min CANCELTIMER one-min CANCELTIMER final-delay')
  conf.append('# End of timed plan specific actions')
else :
  conf.append('# Standard plan specific actions')
  conf.append('LET Msg-OB = banner " Power failure, possible shutdown, save your work ..."')
  conf.append('WHEN [UPS] REPORTS OL->OB :   NOTIFY Msg-OB NUTLOG Msg-OB WALL Msg-OB')
  conf.append('# End of standard plan specific actions')
conf.append('')
conf.append('# Shutdown on low battery')
conf.append('WHEN [UPS] REPORTS None->LB : NOTIFY Msg-shutdown NUTLOG Msg-shutdown WALL Msg-shutdown')
conf.append('                              STARTTIMER final-delay 5')
conf.append('WHEN [UPS] TIMEOUT final-delay : SHUTDOWNCMD "/sbin/shutdown -h 0"')
conf.append('')
conf.append('# Warning for battery replacement')
conf.append('WHEN [UPS] REPORTS None->RB : NUTLOG Msg-RB NOTIFY Msg-RB STARTTIMER rbwarntime 43200')
conf.append('                              EMAIL FROM [EMAILFROM]')
conf.append('                                    TO   [EMAILTO]')
conf.append('                                    SUBJECT «Msg-RB»')
conf.append('                                    MESSAGE «Msg-RB»')
conf.append('WHEN [UPS] TIMEOUT rbwarntime : NUTLOG Msg-RB NOTIFY Msg-RB STARTTIMER rbwarntime 43200')
conf.append('WHEN [UPS] REPORTS RB->None : CANCELTIMER rbwarntime')
conf.append('')
conf.append('# Warning that UPSmon has lost UPS [UPS].  Shutdown on NOCOMM when OB')
conf.append('WHEN [UPS] REPORTS COMM->NOCOMM : STARTTIMER nocommwarntime 300')
conf.append('                                  IF OL->OB NOTIFY Msg-shutdown')
conf.append('                                  IF OL->OB NUTLOG Msg-shutdown')
conf.append('                                  IF OL->OB WALL Msg-shutdown')
conf.append('                                  IF OL->OB STARTTIMER final-delay 5')
conf.append('WHEN [UPS] TIMEOUT nocommwarntime : NUTLOG Msg-NOCOMM NOTIFY Msg-NOCOMM')
conf.append('WHEN [UPS] REPORTS NOCOMM->COMM : CANCELTIMER nocommwarntime NUTLOG Msg-COMM NOTIFY Msg-COMM')
conf.append('')
conf.append('# Permanent activity')
conf.append('LET Msg-start = banner " Starting permanent activity..."')
conf.append('WHEN [UPS] TIMEOUT start : NUTLOG Msg-start')
conf.append('                           EMAIL FROM [EMAILFROM]')
conf.append('                                 TO   [EMAILTO]')
conf.append('                                 SUBJECT «Msg-start»')
conf.append('                                 MESSAGE «Msg-start»')
conf.append('# Software battery.charge.low levels')
conf.append('LET battery.charge.low.1 = "75" LET battery.charge.low.2 = "50" LET battery.charge.low.3 = "25"')
conf.append('WHEN [UPS] REPORTS None->LB1 : NUTLOG banner WHEN [UPS] REPORTS LB1->None : NUTLOG banner')
conf.append('WHEN [UPS] REPORTS None->LB2 : NUTLOG banner WHEN [UPS] REPORTS LB2->None : NUTLOG banner')
conf.append('WHEN [UPS] REPORTS None->LB3 : NUTLOG banner WHEN [UPS] REPORTS LB3->None : NUTLOG banner')
conf.append('')
conf.append('##############################################################################')
conf.append('# Heartbeat operation, requires file heartbeat.conf in the upsd server, and')
conf.append('# definition of UPS [heartbeat] in ups.conf.  Note that the timers tick-timer')
conf.append('# and tock-timer specified here must be longer than the timer in heartbeat.conf.')
conf.append('GROUP HB HOST [UPSDNAME] PORT [UPSDPORT] CERTFILE Certfile')
conf.append('LET HB-banner    = ⸢[%(b)s] UPS=%(u)s event=%(e)s⸥')
conf.append('LET Msg-HB-start = HB-banner " Starting tick-timer"')
conf.append('LET MSG-HB-fails = HB-banner " FAILURE.  I have not received expected TICK/TOCK status change."')
conf.append('MONITOR heartbeat POWERVAL 0 UPSDUSER [UPSDUSER] PASSWORD [UPSDPASS] TYPE master')
conf.append('MINSUPPLIES 0')
conf.append('WHEN heartbeat REPORTS None->TICK : CANCELTIMER tock-timer STARTTIMER tick-timer 660')
conf.append('                                    NUTLOG Msg-HB-start')
conf.append('WHEN heartbeat REPORTS None->TOCK : CANCELTIMER tick-timer STARTTIMER tock-timer 660')
conf.append('')
conf.append('# What to do if the heartbeat fails')
conf.append('WHEN heartbeat TIMEOUT tick-timer : STARTTIMER tock-timer 0.5')
conf.append('WHEN heartbeat TIMEOUT tock-timer : NUTLOG MSG-HB-fails NOTIFY MSG-HB-fails')
conf.append('                                    EMAIL FROM [EMAILFROM]')
conf.append('                                          TO   [EMAILTO]')
conf.append('                                          SUBJECT «Msg-HB-fails»')
conf.append('                                          MESSAGE «Msg-HB-fails»')
conf.append('# End of file')

# Substitutions have to be quoted if the value is specified as a 'quotetext' in the grammar
for line in conf :
  print(line.replace('[PLAN]',       args.plan[0])\
            .replace('[UPS]',        args.ups[0])\
            .replace('[UPSDNAME]',   args.upsdname[0])\
            .replace('[UPSDPORT]',   args.upsdport[0])\
            .replace('[CERTFILE]',   '«'+args.certfile[0].strip('«»')+'»')\
            .replace('[UPSDUSER]',   args.upsduser[0])\
            .replace('[UPSDPASS]',   '«'+args.upsdpass[0].strip('«»')+'»')\
            .replace('[SMTPSERVER]', '«'+args.smtpserver[0].strip('«»')+'»')\
            .replace('[SMTPPORT]',   args.smtpport[0])\
            .replace('[SMTPUSER]',   '«'+args.smtpuser[0].strip('«»')+'»')\
            .replace('[SMTPPASS]',   '«'+args.smtppass[0].strip('«»')+'»')\
            .replace('[EMAILFROM]',  '«'+args.emailfrom[0].strip('«»')+'»')\
            .replace('[EMAILTO]',    '«'+args.emailto[0].strip('«»')+'»'))

# Adieu
