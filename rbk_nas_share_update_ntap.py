#!/usr/bin/python
from __future__ import print_function
import sys
import getopt
import getpass
import rubrik_cdm
import socket
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

def ntap_invoke_err_check(out):
    if(out.results_status() == "failed"):
            print(out.results_reason() + "\n")
            sys.exit(2)

def ntap_set_err_check(out):
    if(out and (out.results_errno() != 0)) :
        r = out.results_reason()
        print("Connection to filer failed" + r + "\n")
        sys.exit(2)

def find_missing_hosts(rubrik, svm_list, config):
    missing_hosts = []
    nas_hosts = []
    hosts = rubrik.get('v1', '/host?operating_system_type=NONE')
    for host in hosts['data']:
        nas_hosts.append(host['hostname'])
    for svm_host in svm_list:
        if (svm_host not in nas_hosts) and (svm_host not in config['exclude_host']):
            missing_hosts.append(svm_host)
    return(missing_hosts)

def add_ntap_host(rubrik, missing_hosts, config):
    return()


def ntap_get_share_list(host, protocol, svm_list, svm_only, config):
    addr = ""
    hostname = {}
    host_lookup = ()

# Set up NetApp API session

    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    netapp = NaServer(host, 1, 130)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(config['array_user'], config['array_password'])
    ntap_set_err_check(out)

# Get list of SVMs from NetApp

    if svm_list == {}:
        result = netapp.invoke('vserver-get-iter')
        ntap_invoke_err_check(result)
        vs_info = result.child_get('attributes-list').children_get()
        for vs in vs_info:
            vs_type = vs.child_get_string("vserver-type")
            if vs_type == "data":
                svm_list[vs.child_get_string('vserver-name')] = ""

# Get list of interfaces on the NetApp.  Find the an applicable interface, grab the IP,
# then try to get a hostname from it via DNS

    for svm in svm_list.keys():
        netapp.set_vserver(svm)
        print ("SVM_INT: " + svm)
        result = netapp.invoke('net-interface-get-iter')
        ntap_invoke_err_check(result)
        try:
            ints = result.child_get('attributes-list').children_get()
        except AttributeError:
            continue
        for i in ints:
            protocols = i.child_get('data-protocols').children_get()

            # Couldn't figure out how to pull the protocols properly, nasty hack.  Should clean up later

            for p in protocols:
                proto = p.sprintf()
                proto = proto.replace('<', '>')
                pf = proto.split('>')
                if pf[2] == "nfs" or pf[2] == "cifs":
                    addr = i.child_get_string('address')
                    try:
                        host_lookup = socket.gethostbyaddr(addr)
                        svm_list[svm] = host_lookup[0]
                    except socket.herror:
                        svm_list[svm] = addr
    if svm_only:
        return(svm_list)

# For each SVM, grab the NFS exports of SMB shares.  Generate the share_list structure for main()

    for svm in svm_list.keys():
        svm_share_list = []
        junct_point = {}
        if svm in config['exclude_hosts']:
            continue
        out = netapp.set_vserver(svm)
        if protocol == "nfs":
            result = netapp.invoke('volume-get-iter')
            ntap_invoke_err_check(result)
            vol_attrs = result.child_get('attributes-list').children_get()
            for v in vol_attrs:
                vid_attrs = v.child_get('volume-id-attributes')
                volume = vid_attrs.child_get_string('name')
                junction = vid_attrs.child_get_string('junction-path')
                junct_point[volume] = junction
            result = netapp.invoke('qtree-list-iter')
            ntap_invoke_err_check(result)
            qt_attrs = result.child_get('attributes-list').children_get()
            for qt in qt_attrs:
                volume = qt.child_get_string('volume')
                qtree = qt.child_get_string('qtree')
                if qtree == "":
                    vol_j = junct_point[volume]
                else:
                    vol_j = junct_point[volume] + "/" + qtree
                if vol_j != "/":
                    svm_share_list.append(vol_j)
        elif protocol == "cifs" or protocol == "smb":
            result = netapp.invoke('cifs-share-get-iter')
            ntap_invoke_err_check(result)
            attr = result.child_get('attributes-list').children_get()
            for sh in attr:
                path = sh.child_get_string('path')
                if path == "/":                                 # Exclude root volumes
                    continue
                svm_share_list.append(sh.child_get_string('share-name'))
        share_list[hostname[svm]] = svm_share_list
    return (share_list)

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
    svm_list = {}
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
            for s in a.split(','):
                svm_list[s] = ""
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

    if config['rubrik_user'] == "":
        config['rubrik_user'] = python_input("Rubrik User: ")
    if config['rubrik_password'] == "":
        config['rubrik_password'] = getpass.getpass("Rubrik Password: ")
    if config['array_user'] == "":
        config['array_user'] = python_input("Isilon User: ")
    if config['array_password'] == "":
        config['array_password'] = getpass.getpass("Isilon Password: ")

    rubrik = rubrik_cdm.Connect (rubrik_host, config['rubrik_user'], config['rubrik_password'])
    svm_list = ntap_get_share_list(ntap_host, '', svm_list, True, config)
    dprint("SVM: " + str(svm_list))
    missing_hosts = find_missing_hosts(rubrik, svm_list, config)
    if missing_hosts:
        print("Missing Hosts: " + str(missing_hosts))
        if not REPORT_ONLY:
            add_ntap_host(rubrik, missing_hosts, config)
