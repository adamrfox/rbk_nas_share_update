#!/usr/bin/python

from __future__ import print_function
import sys
import getopt
import getpass
import rubrik_cdm
import subprocess
import copy
import urllib3
urllib3.disable_warnings()

def usage():
    sys.stderr.write("Usage: rbk_nas_share_update_nfs.py [-hDrC] [-c config_file] nfs_server rubrik\n")
    sys.stderr.write("-h | --help : Prints this message\n")
    sys.stderr.write("-D | --DEBUG : Turns debug printing on\n")
    sys.stderr.write("-r | --report_only : Don't add any shares, just show what would be added\n")
    sys.stderr.write("-C | --dump_config : Show the config variables only\n")
    sys.stderr.write("-c | --config : specifiy a config file\n")
    sys.stderr.write("nfs_server : Name or IP of the NFS server\n")
    sys.stderr.write("rubrik : Name or IP of Rubrik\n")
    exit(0)

def python_input(message):
    if int(sys.version[0]) > 2:
        value = input(message)
    else:
        value = raw_input(message)
    return(value)

def dprint(message):
    if DEBUG:
        dfh = open(debug_log, 'a')
        dfh.write(message + "\n")
        dfh.close()

def get_export_list(nas_host, cfg_data):
    export_list =[]
    done = False

    exportfs = subprocess.Popen([cfg_data['showmount'], '-e', nas_host], stdout=subprocess.PIPE)
    while not done:
        line = exportfs.stdout.readline()
        if int(sys.version[0]) > 2:
            line = str(line.decode('utf-8'))
        if not line:
            done = True
        else:
            if not line.startswith("/"):
                continue
            lf = line.split()
            if lf[0] != "/":
                export_list.append(lf[0])
    return (export_list)

def get_rubrik_share_list (nas_host, hs_data):
    share_list = []
    for share in hs_data['data']:
        if share['hostname'] == nas_host:
            share_list.append(str(share['exportPoint']))
    return(share_list)

def list_compare(array_list, rubrik_list, config):
    add_list = []
    for export in array_list:
        exclude = False
        for ex_path in config['exclude_path']:
            if export.startswith(ex_path):
                exclude = True
                break
        if export not in rubrik_list and not exclude:
            add_list.append(export)
    return(add_list)

def get_host_id(rubrik, nas_host):
    try:
        hosts = rubrik.get('v1', '/host?operating_system_type=NONE', timeout=60)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Error calling hosts: " + str(e))
        return("")
    for h in hosts['data']:
        if h['hostname'] == nas_host:
            return(h['id'])
    return("")

def get_fileset_id(rubrik, fs_name):
    try:
        fs_data = rubrik.get('v1', '/fileset_template?name=' + fs_name, timeout=60)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Error calling fileset_template: " + str(e))
        return("")
    for fs in fs_data['data']:
        if fs['name'] == fs_name:
            return(fs['id'])
    return("")

def get_sla_id(rubrik, sla_name):
    try:
        sla_data = rubrik.get('v2', '/sla_domain?primary_cluster_id=local&name=' + sla_name)
    except rubrik_cdm.exceptions.APICallException as e:
        sys.stderr.write("Error calling sla_domain: " + str(e))
        return ("")
    for sla in sla_data['data']:
        if sla['name'] == sla_name:
            return(sla['id'])
    return("")

def dump_config (config):
    cfg_copy = copy.deepcopy(config)
    for k in cfg_copy:
        if k.find('password') >= 0:
            cfg_copy[k] = "*********"
    dprint(cfg_copy)

def get_config_from_file(cfg_file):
    cfg_data = {}
    cfg_options = ['rubrik_user', 'rubrik_password', 'rubrik_token', 'default_fileset', 'default_sla', 'nas_da',
                   'purge_overlaps', 'showmount']
    cfg_list_options = ['exclude_path']
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
        cfg_data['purge_overlaps']
    except KeyError:
        cfg_data['purge_overlaps'] = 'false'
    try:
        cfg_data['showmount']
    except KeyError:
        cfg_data['showmount'] = "/usr/sbin/showmount"
    if cfg_data['showmount'] == "":
        cfg_data['showmount'] = "/usr/sbin/showmount"
    return(cfg_data)

if __name__ == "__main__":
    export_list = {}
    rubrik_export_list = {}
    config = {}
    DEBUG = False
    DUMP_CONFIG = False
    REPORT_ONLY = False
    debug_log = "debug_log.txt"

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:DrC', ['--help', '--config=', '--DEBUG', '--report', '--dump_config'])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-c', '--config'):
           config = get_config_from_file(a)
        if opt in ('-D', '--DEBUG'):
            VERBOSE = True
            DEBUG = True
        if opt in ('-r' , '--report_only'):
            REPORT_ONLY = True
        if opt in ('-C', '--dump_config'):
            DUMP_CONFIG = True
            DEBUG = True
            dfh = open(debug_log, "w")
            dfh.close()
    if not DUMP_CONFIG:
        try:
            (nas_host, rubrik_host) = args
        except ValueError:
            usage()
    if DEBUG or DUMP_CONFIG:
        dump_config(config)
    if DUMP_CONFIG:
        exit(0)
    if 'rubrik_user' not in config.keys() and 'rubrik_token' not in config.keys():
        config['rubrik_user'] = python_input("Rubrik User: ")
    if 'rubrik_password' not in config.keys() and 'rubrik_token' not in config.keys():
        config['rubrik_password'] = getpass.getpass("Rubrik Password: ")
    if 'rubrik_token' not in config.keys():
        rubrik = rubrik_cdm.Connect(rubrik_host, config['rubrik_user'], config['rubrik_password'])
    else:
        rubrik = rubrik_cdm.Connect(rubrik_host, api_token=config['rubrik_token'])
    hs_data = rubrik.get('internal', '/host/share?share_type=NFS', timeout=60)
    export_list = get_export_list(nas_host, config)
    dprint("EXPORT_LIST = " + str(export_list))
    rubrik_export_list = get_rubrik_share_list(nas_host, hs_data)
    dprint("RBK_EXPORT_LIST: " + str(rubrik_export_list))
    nfs_add_list = list_compare(export_list, rubrik_export_list, config)
    print("Exports to add: " + str(nfs_add_list))
    if not REPORT_ONLY:
        skipped_shares = []
        host_id = get_host_id(rubrik, nas_host)
        if not host_id:
            sys.stderr.write("Can't find NAS host " + nas_host + " on Rubrik\n")
            exit(1)
        if config['default_fileset']:
            fs_id = get_fileset_id(rubrik, config['default_fileset'])
            if not fs_id:
                sys.stderr.write("Can't find fileset " + config['default_fileset'] + "\n")
        if config['default_sla']:
            sla_id = get_sla_id(rubrik, config['default_sla'])
            if not sla_id:
                sys.stderr.write("Can't find SLA " + config['default_sla_name'] + "\n")
        for add_export in nfs_add_list:
            print("Adding " + add_export)
            payload = {'hostId': host_id, 'shareType': 'NFS', 'exportPoint': add_export}
            try:
                share_id = rubrik.post('internal', '/host/share', payload, timeout=60)['id']
            except rubrik_cdm.exceptions.APICallException as e:
                sys.stderr.write("Export add failed: " + str(e))
                skipped_shares.append(add_export)
                continue
            if config['default_fileset'] and fs_id:
                payload = {'shareId': share_id, 'templateId': fs_id}
                if str(config['nas_da']).lower() == "true":
                    payload['isPassthrough'] = True
                try:
                    fs_add = rubrik.post('v1', '/fileset', payload, timeout=60)
                except rubrik_cdm.exceptions.APICallException as e:
                    sys.stderr.write("Export add failed: " + str(e))
                    continue
            if config['default_sla'] and sla_id:
                payload = {'managedIds': [fs_add['id']]}
                dprint("PAYLOAD: " + str(payload))
                try:
                    sla_add = rubrik.post('v2', '/sla_domain/' + str(sla_id) + '/assign', payload, timeout=60)
                except rubrik_cdm.exceptions.APICallException as e:
                    sys.stderr.write("SLA add failed: " + str(e))
                    continue
        if skipped_shares:
            print("Could not add: " + str(skipped_shares))
