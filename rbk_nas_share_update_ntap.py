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
    print ("NAS_HOSTS: " + str(nas_hosts))
    print ("SVM_LIST: " + str(svm_list))
    for svm_host in svm_list.values():
        if svm_host == "":
            continue
        if (svm_host not in nas_hosts) and (svm_host not in config['exclude_host']):
            missing_hosts.append(svm_host)
    return(missing_hosts)

def add_ntap_host(rubrik, missing_hosts, config):
    add_hosts = []
    for nas in missing_hosts:
        print("Adding NetApp Host: " + nas)
        if str(config['array_scan']).lower() == "true":
            add_hosts.append({'hostname': nas, 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'isNetAppSnapDiffEnabled': True}})
        else:
            add_hosts.append({'hostname': nas, 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password']}})

    dprint("Host Add: " + str(add_hosts))
    nas_result = rubrik.post('internal', '/host/bulk', add_hosts, timeout=60)
    if config['smb_user']:
        (user, domain) = config['smb_user'].split('@')
        for nas in nas_result['data']:
            nas_creds = {'hostId': str(nas['id']), 'domain': domain, 'username': user, 'password': config['smb_password']}
            dprint("NAS_ADD: " + str(nas_creds))
            nas_creds_result = rubrik.post('internal', '/host/share_credential', nas_creds, timeout=60)


def get_rubrik_share_list(protocol, az_list, hs_data):
    share_data = {}
    for zone in az_list:
        share_list = []
        share_data[zone] = share_list
        for share in hs_data['data']:
            if share['hostname'] == az_list[zone] and share['shareType'] == protocol:
                share_list.append(str(share['exportPoint']))
        share_data[az_list[zone]] = share_list
    return (share_data)

def list_compare(array_list, rubrik_list, config):
    add_list = {}
#    print ("ARRAY: " + str(array_list))
    for zone in array_list:
        shares_to_add = []
        if zone not in config['exclude_host']:
            for share_data in array_list[zone]:
                (share, path) = share_data.split(':')
                if share not in config['exclude_share']:
                    for ex_path in config['exclude_path']:
                        if path.startswith(ex_path):
                            continue
                        if share not in rubrik_list[zone]:
                            shares_to_add.append(share)
        add_list[zone] = shares_to_add
    return(add_list)

def ntap_get_svm_list(host, protocol, config):
    addr = ""
    hostname = {}
    host_lookup = ()
    share_list = {}
    host_list = {}

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
        print("DEB: SVM: " + svm)
        int_list = []
        netapp.set_vserver(svm)
        result = netapp.invoke('net-interface-get-iter')
        ntap_invoke_err_check(result)
        try:
            ints = result.child_get('attributes-list').children_get()
        except AttributeError:
            continue
        for i in ints:
            int_name = i.child_get_string('interface-name')
            protocols = i.child_get('data-protocols').children_get()
            addr = i.child_get_string('address')
            try:
                host_lookup = socket.gethostbyaddr(addr)
                addr = host_lookup[0]
            except socket.herror:
                pass
            # Couldn't figure out how to pull the protocols properly, nasty hack.  Should clean up later
            proto_list = []
            for p in protocols:
                proto = p.sprintf()
                proto = proto.replace('<', '>')
                pf = proto.split('>')
                proto_list.append(pf[2])
            int_list.append({'address': addr, "protocols": proto_list})
            cand_list = []
            for int_cand in int_list:
                print ("CAND: " + str(int_cand))
                if protocol == "nfs,cifs":
                    if int_cand['protocols'] == ['nfs', 'cifs']:
                        cand_list = [int_cand['address']]
                        break
                    elif int_cand['protocols'] == "nfs":
                        cand_list.append(int_cand['address'])
                    elif int_cand['protocols'] == "cifs":
                        cand_list.append(int_cand['address'])
                elif protocol == "nfs":
                    if int_cand['protocols'] == ["nfs"]:
                        cand_list = [int_cand['address']]
                        break
                    elif int_cand['protocols'] == "nfs,cifs":
                        cand_list.append(int_cand['address'])
                elif protocol == "cifs":
                    if int_cand['protocols'] == ["cifs"]:
                        cand_list = [int_cand['address']]
                        break
                    elif int_cand['protocols'] == ["nfs","cifs"]:
                        cand_list.append(int_cand['address'])
            host_list[svm] = cand_list
    return(host_list)
"""
            for p in protocols:
                proto = p.sprintf()
                proto = proto.replace('<', '>')
                pf = proto.split('>')
                found = False
                if "smb" in protocol and "cifs" in pf[2]:
                    addr = i.child_get_string('address')
                    found = True
                elif "nfs" in protocol and "nfs" in pf[2]:
                    addr = i.child_get_string('address')
                    found = True
                if found:
                    try:
                        host_lookup = socket.gethostbyaddr(addr)
                        svm_list[svm] = host_lookup[0]
                    except socket.herror:
                        svm_list[svm] = addr

    if svm_only:
        return (svm_list)
"""
def new_func():
    dprint("SVM_LIST2: " + str(svm_list))
    # For each SVM, grab the NFS exports of SMB shares.  Generate the share_list structure for main()
    for svm in svm_list.keys():
        svm_share_list = []
        junct_point = {}
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
            try:
                attr = result.child_get('attributes-list').children_get()
            except AttributeError:
                continue
            for sh in attr:
                path = sh.child_get_string('path')
                sh_name = sh.child_get_string('share-name')
                if path == "/":                                 # Exclude root volumes
                    continue
                svm_share_list.append(sh_name + ":" + path)
        share_list[svm_list[svm]] = svm_share_list
    return (share_list)

def get_hostid_from_nas_data(host, nas_host_data):
    for host_inst in nas_host_data['data']:
        if host_inst['hostname'] == host:
            return (host_inst['id'])

def add_ntap_shares(rubrik, host, protocol, add_list, svm_list, nas_host_data, config):
    dprint("ADD_LIST: " + str(add_list))
    for nas_host in add_list:
        host_id = get_hostid_from_nas_data(nas_host, nas_host_data)
        skipped_shares = []
        for share in add_list[nas_host]:
            payload = {'hostId': host_id, 'shareType': protocol.upper(), 'exportPoint': share}
            dprint("PAYLOAD: " + str(payload))



def get_config_from_file(cfg_file):
    cfg_data = {}
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
    rubrik_share_list = {}
    export_list = []
    rubrik_export_list = {}
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
    if smb and not nfs:
        p_str = "cifs"
    elif not smb and nfs:
        p_str = "nfs"
    else:
        p_str = "nfs,cifs"
    rubrik = rubrik_cdm.Connect (rubrik_host, config['rubrik_user'], config['rubrik_password'])
    svm_list = ntap_get_svm_list(ntap_host, p_str, config)
    dprint("SVM_LIST1: " + str(svm_list))
    missing_hosts = find_missing_hosts(rubrik, svm_list, config)
    dprint("MISSING HOSTS: " + str(missing_hosts))
    if missing_hosts:
        print("Missing Hosts: " + str(missing_hosts))
        if not REPORT_ONLY:
            add_ntap_host(rubrik, missing_hosts, config)
    nas_host_data = rubrik.get('v1', '/host?operating_system_type=NONE')
    hs_data = rubrik.get('internal', '/host/share')
    if smb:
        share_list = ntap_get_share_list(ntap_host, 'smb', svm_list, False, config)
        dprint("SMB SHARE LIST: " + str(share_list))
        rubrik_share_list = get_rubrik_share_list('SMB', svm_list, hs_data)
        dprint("RBK SHARE LIST: " + str(rubrik_share_list))
        smb_add_list = list_compare(share_list, rubrik_share_list, config)
        print ("Shares to add: " + str(smb_add_list))
        if not REPORT_ONLY:
            add_ntap_shares(rubrik, ntap_host, 'smb', smb_add_list, svm_list, nas_host_data, config)

