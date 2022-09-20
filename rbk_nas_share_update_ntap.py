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
    sys.stderr.write("Usage: rbk_nas_share_update_ntap.py [-hrDC] [-s svm_list] [-p protocol] -c config ntap rubrik\n")
    sys.stderr.write("-h | --help : Prints Usage\n")
    sys.stderr.write("-D | --debug : Debug mode. Creates a file with extra debugging info\n")
    sys.stderr.write("-C | --dump_config : Dumps the config to the debug file.  Included with -D\n")
    sys.stderr.write("-r | --report : Only shows what would be updated, updates are not done\n")
    sys.stderr.write("-s | --svms= : Provide a comma-separted list of SVMs to process\n")
    sys.stderr.write("-p | --protocol= : Only process one protocol [nfs|smb]\n")
    sys.stderr.write("-c | --config= : Location of config file [required]\n")
    sys.stderr.write("ntap : Name/IP of the cluster admin LIF of a NTAP cluster\n")
    sys.stderr.write("rubrik : Name/IP of a Rubrik cluster node\n")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open(debug_log, 'a')
        dfh.write(message + "\n")
        dfh.close()

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
    missing_hosts = {}
    nas_hosts = []
    found_host = ""
    exclude = True
    hosts = rubrik.get('v1', '/host?operating_system_type=NONE&primary_cluster_id=local')
    for host in hosts['data']:
        nas_hosts.append(host['hostname'])
    dprint ("NAS_HOSTS: " + str(nas_hosts))
    dprint ("SVM_LIST: " + str(svm_list))
    for svm_hosts in svm_list:
        found = False
        dprint("SVM_HOST: " + str(svm_hosts))
        if svm_hosts in config['exclude_host']:
            exclude = True
        else:
            for svm in svm_list[svm_hosts]:
                exclude = False
                dprint("SVM: " + str(svm))
                found_host = svm['address']
                if svm == "":
                    exclude = True
                    break
                if svm['address'] in nas_hosts:
                    found = True
                    exclude = True
                    break
        dprint("FOUND: " + str(found) + " // EXCL: " + str(exclude))
        if not found and not exclude:
            missing_hosts[svm_hosts] = found_host
    return(missing_hosts, nas_hosts)

def curate_missing_hosts(svm_list, nas_hosts, missing_hosts):
    new_missing_hosts = {}
    for mh in missing_hosts:
        mh_on_rubrik = False
        for i, svm in enumerate(svm_list[mh]):
            if svm_list[mh][i]['address'] in nas_hosts:
                mh_on_rubrik = True
                break
        if not mh_on_rubrik:
            new_missing_hosts[mh] = missing_hosts[mh]
    dprint("NEW_MISSING_HOSTS: " + str(new_missing_hosts))
    return(new_missing_hosts)

def add_ntap_host(rubrik, missing_hosts, config):
    add_hosts = []
    print("MISS: " + str(missing_hosts))
    for host in missing_hosts:
        miss_host = missing_hosts[host]
        print("Adding NetApp Host: " + miss_host)
        if str(config['array_scan']).lower() == "true":
            add_hosts.append({'hostname': miss_host, 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'isNetAppSnapDiffEnabled': True, 'apiHostname': mgmt_lif[host]}})

        else:
            add_hosts.append({'hostname': host_host, 'hasAgent': False, 'nasConfig': {'vendorType': 'NETAPP', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'apiHostname': mgmt_lif[host]}})

    dprint("Host Add: " + str(add_hosts))
    nas_result = rubrik.post('internal', '/host/bulk', add_hosts, timeout=120)
    if config['smb_user']:
        (user, domain) = config['smb_user'].split('@')
        for nas in nas_result['data']:
            nas_creds = {'hostId': str(nas['id']), 'domain': domain, 'username': user, 'password': config['smb_password']}
            dprint("NAS_ADD: " + str(nas_creds))
            nas_creds_result = rubrik.post('internal', '/host/share_credential', nas_creds, timeout=120)


def get_rubrik_share_list(protocol, az_list, hs_data):
    share_data = {}
    for zone in az_list:
        share_list = []
        share_host = get_host_from_svm_list(az_list[zone], nas_hosts, missing_hosts, protocol)
        for share in hs_data['data']:
            if share['hostname'] == share_host and share['shareType'] == protocol.upper():
                share_list.append(str(share['exportPoint']))
        share_data[share_host] = share_list
    return (share_data)

def list_compare(array_list, rubrik_list, config):
    add_list = {}
    dprint ("ARRAY: " + str(array_list))
    dprint("RBK_LIST: " + str(rubrik_list))
    for zone in array_list:
        shares_to_add = []
        if zone not in config['exclude_host']:
            for share_data in array_list[zone]:
                (share, path) = share_data.split(':')
                if share not in config['exclude_share']:
                    for ex_path in config['exclude_path']:
                        if path.startswith(ex_path):
                            continue
                    if share not in rubrik_list[zone] and share != "None":
                        shares_to_add.append(share)
        if shares_to_add:
            add_list[zone] = shares_to_add
    return(add_list)

def ntap_get_svm_list(host, protocol, config):
    addr = ""
    hostname = {}
    host_lookup = ()
    share_list = {}
    host_list = {}
    proto_found = False
    mgmt_found = False
    mgmt_lif = {}
    srv_list = {}

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
            if vs_type == "data" and not vs.child_get_string('vserver-name') in config['exclude_host']:
                svm_list[vs.child_get_string('vserver-name')] = ""

# Get list of interfaces on the NetApp.  Find the applicable interface, grab the IP,
# then try to get a hostname from it via DNS
    for svm in svm_list.keys():
        int_list = []
        netapp.set_vserver(svm)
        result = netapp.invoke('net-interface-get-iter')
        ntap_invoke_err_check(result)
#        print(result.sprintf())
        try:
            ints = result.child_get('attributes-list').children_get()
        except AttributeError:
            continue
        for i in ints:
            int_name = i.child_get_string('interface-name')
            protocols = i.child_get('data-protocols').children_get()
            addr = i.child_get_string('address')
            services = i.child_get('service-names').children_get()
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
            int_srvs = []
            for s in services:
                srv = s.sprintf()
                srv = srv.replace('<', '>')
                sf = srv.split('>')
                int_srvs.append(sf[2])
            int_list.append({'address': addr, "protocols": proto_list, 'services': int_srvs})
        cand_list = []
        for int_cand in int_list:
            if protocol == "nfs,cifs":
                if 'nfs' in int_cand['protocols'] and 'cifs' in int_cand['protocols']:
                    cand_list.append(int_cand)
                    proto_found = True
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand['address']
                            mgmt_found = True
                            break
                elif 'nfs' in int_cand['protocols']:
                    cand_list.append(int_cand)
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand['address']
                            mgmt_found = True
                elif 'cifs' in int_cand['protocols']:
                    cand_list.append(int_cand)
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand['address']
                            mgmt_found = True
                else:
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand['address']
                            mgmt_found = True
            elif not proto_found and 'nfs' in int_cand['protocols']:
                if 'nfs' in int_cand['protocols']:
                    cand_list.append(int_cand)
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand
                            mgmt_found = True
#                           break
                elif not proto_found and ['protocols'] == ["nfs,cifs"]:
                    cand_list.append(int_cand)
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand
                            mgmt_found = True
            elif not mgmt_found and protocol == "cifs":
                if int_cand['protocols'] == ["cifs"]:
                    cand_list.append(int_cand)
                    for svc in int_cand['services']:
                        if svc == "management_https":
                            mgmt_lif[svm] = int_cand
                            mgmt_found = True
#                           break
                elif int_cand['protocols'] == ["nfs","cifs"]:
                    cand_list.append(int_cand)
            elif not mgmt_found:
                for svc in int_cand['services']:
                    if svc == "management_https":
                        mgmt_lif[svm] = int_cand
                        mgmt_found = True
        host_list[svm] = cand_list
    return(host_list, mgmt_lif)

def get_host_from_svm_list(svm, nas_hosts, missing_hosts, protocol):
    if protocol == "smb":
        protocol = "cifs"
    for svm_inst in svm:
        if protocol in svm_inst['protocols'] and svm_inst['address'] in nas_hosts:
            return(svm_inst['address'])
        for mh in missing_hosts:
            if svm_inst['address'] == missing_hosts[mh]:
                return(missing_hosts[mh])
    return("")

def purge_overlapping_shares(share_list, purge_type):
    for svm in share_list.values():
        for x in svm:
            x_split = x.split(':')
            x_val = x_split[1]
            for y in svm:
                y_split = y.split(':')
                y_val = y_split[1]
                if x_val == y_val:
                    continue
                if y_val.startswith(x_val + "/"):
                    if purge_type == "upper":
                        dprint("PURGING " + x)
                        svm.remove(x)
                    elif purge_type == "lower":
                        dprint ("PURGING " + y)
                        svm.remove(y)
    return (share_list)

def ntap_get_share_list(ntap_host, protocol, svm_list, nas_hosts, missing_hosts, config):
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
        share_host = get_host_from_svm_list(svm_list[svm], nas_hosts, missing_hosts, protocol)
        if protocol == "nfs":
            api = NaElement('volume-get-iter')
            l1 = NaElement('desired-attributes')
            api.child_add(l1)
            l2 = NaElement('volume-attributes')
            l1.child_add(l2)
            l2_1 = NaElement('volume-id-attributes')
            l2.child_add(l2_1)
            l2_1.child_add_string('name', '<name>')
            l2_1.child_add_string('junction-path', '<junction-path>')
            l2_2 = NaElement('volume-state-attributes')
            l2.child_add(l2_2)
            l2_2.child_add_string('is-node-root', '<is-node-root>')
            l2_2.child_add_string('is-vserver-root', '<is-vserver-root')
            api.child_add_string('max-records', 5000)
            result = netapp.invoke_elem(api)
            ntap_invoke_err_check(result)
            vol_attrs = result.child_get('attributes-list').children_get()
            for v in vol_attrs:
                vid_attrs = v.child_get('volume-id-attributes')
                vst_attrs = v.child_get('volume-state-attributes')
                node_root = vst_attrs.child_get_string('is-node-root')
                svm_root = vst_attrs.child_get_string('is-vserver-root')
                if node_root == "false" and svm_root == "false":
                    volume = vid_attrs.child_get_string('name')
                    dprint ("FOUND VOL: " + volume)
                    junction = vid_attrs.child_get_string('junction-path')
                    junct_point[volume] = junction
            dprint("JUNCTION_POINTS for " + svm + ": " + str(junct_point))
            api = NaElement('qtree-list-iter')
            l1 = NaElement('desired-attributes')
            api.child_add(l1)
            l2 = NaElement('qtree-info')
            l1.child_add(l2)
            l2.child_add_string('qtree', '<qtree>')
            l2.child_add_string('volume', '<volume>')
            api.child_add_string('max-records', 5000)
            result = netapp.invoke_elem(api)
            ntap_invoke_err_check(result)
            qt_attrs = result.child_get('attributes-list').children_get()
            for qt in qt_attrs:
                volume = qt.child_get_string('volume')
                qtree = qt.child_get_string('qtree')
                if qtree == "":
                    try:
                        vol_j = junct_point[volume]
                    except KeyError:
                        dprint("KEY_ERROR")
                        continue
                else:
                    try:
                        vol_j = junct_point[volume] + "/" + qtree
                    except TypeError:
                        dprint("Flex Group volume?")
                        continue
                if vol_j != "/":
#                if vol_j != "/" and type(vol_j) is unicode:
                    svm_share_list.append(str(vol_j) + ":" + str(vol_j))
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
    if config['purge_overlaps'] != "false":
        dprint("SHARE_LIST: " + str(share_list))
        purge_overlapping_shares(share_list, config['purge_overlaps'])
    return (share_list)

def get_hostid_from_nas_data(host, nas_host_data):
    for host_inst in nas_host_data['data']:
        if host_inst['hostname'] == host:
            return (host_inst['id'])

def get_sla_data(rubrik, sla_name):
    sla_data = rubrik.get('v2', '/sla_domain?primary_cluster=local', timeout=120)
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
        rubrik_fs = rubrik.get('v1', '/fileset_template?name=' + fileset_name, timeout=120)
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
    if config['nas_da'].lower() == "true":
        if sla_name != "":
            (sla_id, has_archive) = get_sla_data(rubrik, sla_name)
            if has_archive:
                payload['isPassthrough'] = True
            else:
                print("Warning: " + sla_name + " does not have an archive.  NAS DA not possible.")
    dprint("PAYLOAD: " + str(payload))
    try:
        fs_add = rubrik.post('v1', '/fileset', payload, timeout=120)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Failed to add fileset: " + str(e))
        return()
    if sla_name != "":
        fs_add_list.append(fs_add['id'])
        (sla_id, has_archive) = get_sla_data(rubrik, sla_name)
        if sla_id == "":
            sys.stderr.write("Can't find SLA: " + sla_name)
            exit(4)
        payload = {'managedIds': fs_add_list}
        dprint("PAYLOAD: " + str(payload))
        try:
            rbk_sla = rubrik.post('internal', '/sla_domain/' + str(sla_id) + '/assign', payload, timeout=120)
        except rubrik_cdm.exceptions.APICallException as e:
            sys.stderr.write("Failed to assign SLA: " + sla_name + " : " + str(e))


def add_ntap_shares(rubrik, protocol, add_list, nas_host_data, config):
    dprint("ADD_LIST: " + str(add_list))
    for nas_host in add_list:
        host_id = get_hostid_from_nas_data(nas_host, nas_host_data)
        skipped_shares = []
        for share in add_list[nas_host]:
            payload = {'hostId': host_id, 'shareType': protocol.upper(), 'exportPoint': share}
            dprint("PAYLOAD: " + str(payload))
            sh_add_flag = True
            try:
                share_id = rubrik.post('internal', '/host/share', payload, timeout=120)['id']
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

def get_share_path(share_list, host, share_name):
    for share in share_list[host]:
        (name, path) = share.split(':')
        if name == share_name:
            return(path)
    return ("")

def prefer_smb_over_nfs(nfs_add_list, share_list):
    hs_nfs = {}
    for svm in nfs_add_list:
        for path in nfs_add_list[svm]:
            purge = False
            for smb_share in share_list[svm]:
                sf = smb_share.split(':')
                if path == sf[1]:
                    purge = True
                    break
            if not purge:
                try:
                    hs_nfs[svm]
                except KeyError:
                    hs_nfs[svm] = []
                hs_nfs[svm].append(path)
    dprint("PREFER NFS LIST: " + str(hs_nfs))
    return(hs_nfs)

def dump_config(config):
    cfg_copy = copy.deepcopy(config)
    for k in cfg_copy:
        if k.find('password') >= 0:
            cfg_copy[k] = "*********"
    dprint(str(cfg_copy))


def get_config_from_file(cfg_file):
    cfg_data = {}
    cfg_options = ['rubrik_user', 'rubrik_password', 'array_user', 'array_password', 'smb_user', 'smb_password',
                   'api_user', 'api_password', 'api_host', 'default_nfs_fileset', 'default_smb_fileset','default_sla',
                   'default_nfs_sla', 'default_smb_sla', 'array_scan', 'nas_da', 'purge_overlaps',
                   'prefer_smb','add_hosts', 'rubrik_token']
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
    try:
        cfg_data['purge_overlaps']
    except KeyError:
        cfg_data['purge_overlaps'] = 'false'
    return(cfg_data)

if __name__ == "__main__":
    svm_list = {}
    share_list = []
    rubrik_share_list = {}
    export_list = []
    rubrik_export_list = {}
    config = {}
    DEBUG = False
    DUMP_CONFIG = False
    REPORT_ONLY = False
    SNAPDIFF = False
    nfs = True
    smb = True
    rbk_nas_hosts = []
    smb_add_list = {}
    debug_log = "debug_log.txt"
    mgmt_lif = {}

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:Ds:rp:C', ['--help', '--config=', '--verbose', '--debug', '--svms=', '--report', '--protocol=', '--dump_config'])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ['-c', '--config']:
            config = get_config_from_file(a)
        if opt in ['-D', '--debug']:
            DEBUG = True
            dfh = open(debug_log, "w")
            dfh.close()
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

    if config['rubrik_token'] == "":
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
    if config['rubrik_token'] == "":
        rubrik = rubrik_cdm.Connect (rubrik_host, config['rubrik_user'], config['rubrik_password'])
    else:
        rubrik = rubrik_cdm.Connect(rubrik_host, api_token=config['rubrik_token'])
    (svm_list, mgmt_lif) = ntap_get_svm_list(ntap_host, p_str, config)
    dprint("SVM_LIST1: " + str(svm_list))
    dprint("MGMT_LIFS: " + str(mgmt_lif))
    if config['add_hosts'] == "true":
        (missing_hosts, nas_hosts) = find_missing_hosts(rubrik, svm_list, config)
        dprint("MISSING HOSTS: " + str(missing_hosts))
        missing_hosts = curate_missing_hosts(svm_list, nas_hosts, missing_hosts)
        if missing_hosts:
            print("Missing Hosts: " + str(missing_hosts))
            if not REPORT_ONLY:
                add_ntap_host(rubrik, missing_hosts, config)
    nas_host_data = rubrik.get('v1', '/host?operating_system_type=NONE')
    hs_data = rubrik.get('internal', '/host/share')
    dprint("RBK_HOST_SHARE: " + str(hs_data))
    if smb:
        share_list = ntap_get_share_list(ntap_host, 'smb', svm_list, nas_hosts, missing_hosts, config)
        dprint("SMB SHARE LIST: " + str(share_list))
        rubrik_share_list = get_rubrik_share_list('smb', svm_list, hs_data)
        dprint("RBK SHARE LIST: " + str(rubrik_share_list))
        smb_add_list = list_compare(share_list, rubrik_share_list, config)
        print ("Shares to add: " + str(smb_add_list))
        if not REPORT_ONLY:
            add_ntap_shares(rubrik, 'smb', smb_add_list, nas_host_data, config)
    if nfs:
        export_list = ntap_get_share_list(ntap_host, 'nfs', svm_list, nas_hosts, missing_hosts, config)
        dprint("NFS EXPORT LIST: " + str(export_list))
        rubrik_export_list = get_rubrik_share_list('nfs', svm_list, hs_data)
        dprint("RBK EXPORT LIST: " + str(rubrik_export_list))
        nfs_add_list = list_compare(export_list, rubrik_export_list, config)
        if config['prefer_smb'].lower() != "false":
            if share_list == {}:
                share_list = ntap_get_share_list(ntap_host, 'smb', svm_list, nas_hosts, missing_hosts, config)
            nfs_add_list = prefer_smb_over_nfs(nfs_add_list, share_list)
        print ("Exports to add: " + str(nfs_add_list))
        if not REPORT_ONLY:
            add_ntap_shares(rubrik, 'nfs', nfs_add_list, nas_host_data, config)

