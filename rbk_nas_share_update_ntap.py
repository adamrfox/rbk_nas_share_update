#!/usr/bin/python
from __future__ import print_function
import sys
import getopt
import getpass
import rubrik_cdm
import urllib3
urllib3.disable_warnings()
sys.path.append('./NetApp')
from NaServer import *
import ssl

def usage():
    print ("Usage goes here")
    exit(0)

def vprint(message):
    if VERBOSE:
        print(message)
    return()

def dprint(message):
    if DEBUG:
        print(message)

def python_input(message):
    if int(sys.version[0]) > 2:
        value = input(message)
    else:
        value = raw_input(message)
    return (value)

def get_config_from_file(cfg_file):
    cfg_data = {}
    print ("GET CONFIG: " + cfg_file)
    cfg_options = ['rubrik_user', 'rubrik_password', 'array_user', 'array_password', 'smb_user', 'smb_password', 'api_user', 'api_password', 'api_host', 'default_nfs_fileset', 'default_smb_fileset','default_sla', 'default_nfs_sla', 'default_smb_sla', 'force_smb_acl', 'array_scan']
    cfg_list_options = ['exclude_host', 'exclude_path', 'exclude_share']
    with open(cfg_file) as fp:
        for n, line in enumerate(fp):
            line = line.rstrip()
            if line == "" or line.startswith('#'):
                continue
            lf = line.split('=')
            if lf[0] in cfg_options:
                cfg_data[lf[0]] = lf[1]
            elif lf[0] in cfg_list_options:
                data = []
                for e in lf[1].split(','):
                    data.append(e)
                cfg_data[lf[0]] = data
            else:
                sys.stderr.write("Unknown config option: " + lf[0] + " line: " + str(n) + "\n")
    fp.close()
    for op in cfg_options:
        try:
            cfg_data[op]
        except KeyError:
            cfg_data[op] = ""
    for op in cfg_list_options:
        try:
            cfg_data[op]
        except KeyError:
            cfg_data[op] = []
    try:
        cfg_data['array_scan']
    except KeyError:
        cfg_data['array_scan'] = 'false'
    return(cfg_data)

if __name__ == "__main__":
    svm_list = []
    share_list = []
    rubrik_share_list = []
    export_list = []
    rubrik_export_list = []
    config = {}
    VERBOSE = False
    DEBUG = False
    DUMP_CONFIG = False
    REPORT_ONLY = False
    SNAPDIFF = False
    nfs = True
    smb = True
    rbk_nas_hosts = []

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:VDsrp:C', ['--help', '--config=', '--verbose', '--debug', '--svms=', '--report', '--protocol=', '--dump_config'])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ['-c', '--config']:
            config = get_config_from_file(a)
        if opt in ['-v', '--verbose']:
            VERBOSE = True
        if opt in ['-D', '--debug']:
            VERBOSE = True
            DEBUG = True
        if opt in ('-s', '--svms'):
            svm_list = a.split(',')
        if opt in ('-r', '--report'):
            REPORT_ONLY = True
        if opt in ('-p', '--protocol'):
            if a == "smb":
                nfs = False
            elif a == "nfs":
                smb = False
        if opt in ('-C', '--dump_config'):
            DEBUG = True
            DUMP_CONFIG = True
    try:
        (ntap_host, rubrik_host) = args
    except ValueError:
        usage()
    dprint ("CONFIG" + str(config))
    if DUMP_CONFIG:
        exit(0)

