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
import copy

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
    dprint ("NAS_HOSTS: " + str(nas_hosts))
    dprint ("SVM_LIST: " + str(svm_list))
    for svm_hosts in svm_list.values():
        for svm in svm_hosts:
            if svm == "":
                continue
            if (svm['address'] not in nas_hosts) and (svm['address'] not in config['exclude_host']):
                missing_hosts.append(svm)
    return(missing_hosts)

def add_ntap_host(rubrik, missing_hosts, config):
    add_hosts = []
    for host in missing_hosts:
        print("Adding NetApp Host: " + host['address'])
        if str(config['array_scan']).lower() == "true":
            add_hosts.append({'hostname': host['address'], 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'isNetAppSnapDiffEnabled': True}})
        else:
            add_hosts.append({'hostname': host['address'], 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password']}})

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
        share_host = get_host_from_svm_list(az_list[zone], protocol)
        for share in hs_data['data']:
            if share['hostname'] == share_host and share['shareType'] == protocol.upper():
                share_list.append(str(share['exportPoint']))
        share_data[share_host] = share_list
    return (share_data)

def list_compare(array_list, rubrik_list, config):
    add_list = {}
    print ("ARRAY: " + str(array_list))
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
                        cand_list = [int_cand]
                        break
                    elif int_cand['protocols'] == ["nfs"]:
                        cand_list.append(int_cand)
                    elif int_cand['protocols'] == ["cifs"]:
                        cand_list.append(int_cand)
                elif protocol == "nfs":
                    if int_cand['protocols'] == ["nfs"]:
                        cand_list = [int_cand]
                        break
                    elif int_cand['protocols'] == ["nfs,cifs"]:
                        cand_list.append(int_cand)
                elif protocol == "cifs":
                    if int_cand['protocols'] == ["cifs"]:
                        cand_list = [int_cand]
                        break
                    elif int_cand['protocols'] == ["nfs","cifs"]:
                        cand_list.append(int_cand)
            host_list[svm] = cand_list
    return(host_list)

def get_host_from_svm_list(svm, protocol):
    if protocol == "smb":
        protocol = "cifs"
    for svm_inst in svm:
        if protocol in svm_inst['protocols']:
            return(svm_inst['address'])
    return("")

def ntap_get_share_list(ntap_host, protocol, svm_list, config):
    share_list = {}
    dprint("SVM_LIST2: " + str(svm_list))
    # Set up NetApp API session
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    netapp = NaServer(ntap_host, 1, 130)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(config['array_user'], config['array_password'])
    ntap_set_err_check(out)

    # For each SVM, grab the NFS exports of SMB shares.  Generate the share_list structure for main()

    for svm in svm_list.keys():
        svm_share_list = []
        junct_point = {}
        out = netapp.set_vserver(svm)
        share_host = get_host_from_svm_list(svm_list[svm], protocol)
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
                print ("JP: " + str(junct_point))
                print ("VOL: " + volume)
                print ("QTREE: " + qtree)
                if qtree == "":
                    try:
                        vol_j = junct_point[volume]
                    except KeyError:
                        continue
                else:
                    vol_j = junct_point[volume] + "/" + qtree
                print ("VJ_TYPE: " + str(type(vol_j)))
                if vol_j != "/" and type(vol_j) is unicode:
                    svm_share_list.append(vol_j + ":" + vol_j)
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
        share_list[share_host] = svm_share_list
    return (share_list)

def get_hostid_from_nas_data(host, nas_host_data):
    for host_inst in nas_host_data['data']:
        if host_inst['hostname'] == host:
            return (host_inst['id'])

def get_sla_data(rubrik, sla_name):
    sla_data = rubrik.get('v2', '/sla_domain?primary_cluster=local', timeout=60)
    sla_id = ""
    has_archive = False
    for sld in sla_data['data']:
        if sld['name'] == sla_name:
            sla_id = sld['id']
            if len(sld['archivalSpecs']) > 0:
                has_archive = True
            break
    return (sla_id, has_archive)

def add_fileset_and_sla_to_share(rubrik, config, share_id, protocol):
    sla_name = ""
    if protocol == "smb":
        fileset_name = config['default_smb_fileset']
        if config['default_smb_sla'] != "":
            sla_name = config['default_smb_sla']
        elif config['default_sla'] != "":
            sla_name = config['default_sla']
    else:
        fileset_name = config['default_nfs_fileset']
        if config['default_nfs_sla'] != "":
            sla_name = config['default_nfs_sla']
        elif config['default_sla']:
            sla_name = config['default_sla']
    try:
        rubrik_fs = rubrik.get('v1', '/fileset_template?name=' + fileset_name, timeout=60)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Exception callign filset_template: " + str(e) + "\n")
        exit(2)
    fs_id = ""
    fs_add_list = []
    for fs in rubrik_fs['data']:
        if fs['name'] == fileset_name:
            fs_id = fs['id']
            break
    if fs_id == "":
        sys.stderr.write("Can't find fileset template: " + fileset_name)
        exit(3)
    payload = {'shareId': share_id, 'templateId': fs_id}
    if config['array_scan'].lower() == "true":
        if sla_name != "":
            (sla_id, has_archive) = get_sla_data(rubrik, sla_name)
            if has_archive:
                payload['isPassthrough'] = True
            else:
                print("Warning: " + sla_name + " does not have an archive.  NAS DA not possible.")
    dprint("PAYLOAD: " + str(payload))
    try:
        fs_add = rubrik.post('v1', '/fileset', payload, timeout=60)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Failed to add fileset: " + str(e))
        return()
    if sla_name != "":
        fs_add_list.append(fs_add['id'])
        if sla_id == "":
            sys.stderr.write("Can't find SLA: " + sla_name)
            exit(4)
        payload = {'managedIds': fs_add_list}
        dprint("PAYLOAD: " + str(payload))
        try:
            rbk_sla = rubrik.post('internal', '/sla_domain/' + str(sla_id) + '/assign', payload, timeout=60)
        except rubrik_cdm.exceptions.APICallException as e:
            sys.stderr.write("Failed to assign SLA: " + sla_name + " : " + str(e))


def add_ntap_shares(rubrik, host, protocol, add_list, svm_list, nas_host_data, config):
    dprint("ADD_LIST: " + str(add_list))
    for nas_host in add_list:
        host_id = get_hostid_from_nas_data(nas_host, nas_host_data)
        skipped_shares = []
        for share in add_list[nas_host]:
            payload = {'hostId': host_id, 'shareType': protocol.upper(), 'exportPoint': share}
            dprint("PAYLOAD: " + str(payload))
            sh_add_flag = True
            try:
                share_id = rubrik.post('internal', '/host/share', payload, timeout=60)['id']
            except rubrik_cdm.exceptions.APICallException as e:
                sys.stderr.write("Share add failed: : " + str(e) + "\n")
                sh_add_flag = False
                skipped_shares.append(share)
            if sh_add_flag:
                if (protocol == "smb" and config['default_smb_fileset']) or \
                        (protocol == "nfs" and config['default_nfs_fileset']):
                    add_fileset_and_sla_to_share(rubrik, config, share_id, protocol)
        if skipped_shares:
            print("Failed Shares on " + nas_host + ": " + str(skipped_shares))


def dump_config (config):
    cfg_copy = copy.deepcopy(config)
    for k in cfg_copy:
        if k.find('password') >= 0:
            cfg_copy[k] = "*********"
    dprint(cfg_copy)


def get_config_from_file(cfg_file):
    cfg_data = {}
    cfg_options = ['rubrik_user', 'rubrik_password', 'array_user', 'array_password', 'smb_user', 'smb_password', 'api_user', 'api_password', 'api_host', 'default_nfs_fileset', 'default_smb_fileset','default_sla', 'default_nfs_sla', 'default_smb_sla', 'force_smb_acl', 'array_scan', 'nas_da']
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
        if not DUMP_CONFIG:
            usage()
    if DEBUG:
        dump_config(config)
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
    dprint("RBK_HOST_SHARE: " + str(hs_data))
    if smb:
        share_list = ntap_get_share_list(ntap_host, 'smb', svm_list, config)
        dprint("SMB SHARE LIST: " + str(share_list))
        rubrik_share_list = get_rubrik_share_list('smb', svm_list, hs_data)
        dprint("RBK SHARE LIST: " + str(rubrik_share_list))
        smb_add_list = list_compare(share_list, rubrik_share_list, config)
        print ("Shares to add: " + str(smb_add_list))
        if not REPORT_ONLY:
            add_ntap_shares(rubrik, ntap_host, 'smb', smb_add_list, svm_list, nas_host_data, config)
    if nfs:
        export_list = ntap_get_share_list(ntap_host, 'nfs', svm_list, config)
        dprint("NFS EXPORT LIST: " + str(export_list))
        rubrik_export_list = get_rubrik_share_list('nfs', svm_list, hs_data)
        dprint("RBK EXPORT LIST: " + str(rubrik_export_list))
        nfs_add_list = list_compare(export_list, rubrik_export_list, config)
        print ("Exports to add: " + str(nfs_add_list))
        if not REPORT_ONLY:
            add_ntap_shares(rubrik, ntap_host, 'nfs', nfs_add_list, svm_list, nas_host_data, config)


##TODO Deal with volume shares that aren't root
##TODO Think about SMB over-riding NFS
