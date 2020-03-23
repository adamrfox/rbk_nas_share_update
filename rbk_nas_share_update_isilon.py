#!/usr/bin/python
from __future__ import print_function

import sys
import getopt
import getpass
import isi_sdk_8_0
from isi_sdk_8_0.rest import ApiException
import rubrik_cdm
import ipaddress
import urllib3
urllib3.disable_warnings()


def usage():
    sys.stderr.write("Usage: rbk_nas_share_updade.py [-hDFr] [-c config] [-z zone_list] [-p protocol] isilon rubrik\n")
    sys.stderr.write("-h | --help: Prints this message\n")
    sys.stderr.write("-D | --DEBUG : Debug mode\n")
    sys.stderr.write("-F | --force_acl : Force an SMB ACL (overrides the config file)\n")
    sys.stderr.write("-r | --report : Only show what will be added.  No changes will be made.\n")
    sys.stderr.write("-c | --config file : Config file\n")
    sys.stderr.write("-p | --protocol nfs|smb : Only update the specified protocol [default both]\n")
    sys.stderr.write("-z | --zones zone_list : Only update the specific access zones (comma separated) [default: all]\n")
    sys.stderr.write("isilon : Name/IP of the Isilon (system zone)\n")
    sys.stderr.write("rubrik : Name/IP of the Rubrik Cluster\n")
    exit(0)

def python_input (message):
    if int(sys.version[0]) > 2:
        value = input (message)
    else:
        value = raw_input(message)
    return (value)

def dprint (message):
    if DEBUG:
        print(message)

def vprint (message):
    if VERBOSE or DEBUG:
        print (message)

def isln_get_share_list(host, user, password, protocol, zone_only, az_list, config):
    hostname = {}
    sh_list = {}
    export_id_list = {}

# Set up Isilon API Session

    configuration = isi_sdk_8_0.Configuration()
    configuration.host = "https://" + host + ":8080"
    configuration.username = user
    configuration.password = password
    configuration.verify_ssl = False
    isilon = isi_sdk_8_0.ApiClient(configuration)

# Generate Access Zone list if not given on CLI
    dprint("AZ_LIST: " + str(az_list))
    if not az_list:
        isilon_zones = isi_sdk_8_0.ZonesApi(isilon)
        try:
            result = isilon_zones.list_zones()
        except ApiException as e:
            sys.stderr.write("Error calling list_zones: " + str(e) + "\n")
            exit (1)
        for z in result.zones:
            if z not in config['exclude_host']:
                az_list.append(z.name)

# Look at Network pools, find an applicable pool for each access zone.  Grab the SC Zone name if available

    isilon_network = isi_sdk_8_0.NetworkApi(isilon)
    try:
         result_pools = isilon_network.get_network_pools()
    except ApiException as e:
        sys.stderr.write("Error calling network_pools: " + str(e) + "\n")
        exit(1)
    for p in result_pools.pools:
        if p.access_zone in hostname.keys() or p.access_zone not in az_list:
            continue
        if p.sc_dns_zone:
            hostname[p.access_zone] = p.sc_dns_zone
        else:
            hostname[p.access_zone] = p.ranges[0].low
    if zone_only:
        return (hostname)
# For each access zone, grab the NFS exports or SMB shares.  Generate the share_list structure for main()

    for zone in az_list:
        alias_instance = ()
        al_list = []
        zone_share_list = []
        isilon_protocols = isi_sdk_8_0.ProtocolsApi(isilon)
        if protocol == "nfs":
            try:
                result_aliases = isilon_protocols.list_nfs_aliases(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling nfs_aliases: " + str(e) + "\n")
                exit(1)
            for alias in result_aliases.aliases:
                alias_instance = (alias.name, alias.path)
                al_list.append(alias_instance)
            try:
                results_exports = isilon_protocols.list_nfs_exports(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling nfs_exports: " + str(e) + "\n")
                exit(1)
            for x in results_exports.exports:
                for p in x.paths:
                    if p == "/ifs":                         # Exclude a root export
                        continue
                    found_alias = False
                    for a in al_list:
                        if p in a:
                            zone_share_list.append(a[0] + ":" + p)
                            export_id_list[a[0]] = x.id
                            found_alias = True
                    if not found_alias:
                        zone_share_list.append(p + ":" + p)
                        export_id_list[p] = x.id
        elif protocol == "smb" or protocol == "cifs":
            try:
                results_exports = isilon_protocols.list_smb_shares(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling smb_shares: " + str(e) + "\n")
                exit(1)
            for x in results_exports.shares:
                if x.path == "/ifs":                        # Exclude any /ifs root shares
                    continue
                zone_share_list.append(x.name + ":" + x.path)
        try:
            sh_list[hostname[zone]] = zone_share_list
        except KeyError:
            continue
    return (sh_list, export_id_list)

def get_rubrik_share_list(protocol, az_list, hs_data):
    share_data = {}
    for zone in az_list:
        share_list = []
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

def find_missing_hosts(rubrik, az_list, config):
    missing_hosts = []
    nas_hosts = []
    hosts = rubrik.get('v1', '/host?operating_system_type=NONE')
    for host in hosts['data']:
        nas_hosts.append(host['hostname'])
    for zone_host in az_list.values():
        if (zone_host not in nas_hosts) and (zone_host not in config['exclude_host']):
            missing_hosts.append(zone_host)
    return(missing_hosts)

def add_isilon_host(rubrik, missing_hosts, config):
    add_hosts = []
    for nas in missing_hosts:
        print("Adding Isilon Host: " + nas)
        if str(config['array_scan']).lower() == "true":
            add_hosts.append({'hostname': nas, 'hasAgent': False, 'nasConfig': {'vendorType': 'ISILON', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'apiHostname': config['api_host'], 'isIsilonChangelistEnabled': True}})
        else:
            add_hosts.append({'hostname': nas, 'hasAgent': False, 'nasConfig': {'vendorType': 'ISILON', 'apiUsername': config['api_user'], 'apiPassword': config['api_password'], 'apiHostname': config['api_host']}})

    dprint("Host Add: " + str(add_hosts))
    nas_result = rubrik.post('internal', '/host/bulk', add_hosts, timeout=60)
    if config['smb_user']:
        (user, domain) = config['smb_user'].split('@')
        for nas in nas_result['data']:
            nas_creds = {'hostId': str(nas['id']), 'domain': domain, 'username': user, 'password': config['smb_password']}
            dprint("NAS_ADD: " + str(nas_creds))
            nas_creds_result = rubrik.post('internal', '/host/share_credential', nas_creds, timeout=60)

def get_zone_from_name(host, az_list):
    for zone in az_list:
        if az_list[zone] == host:
            return(zone)
    return ("")

def get_hostid_from_nas_data(host, nas_host_data):
    for host_inst in nas_host_data['data']:
        if host_inst['hostname'] == host:
            return (host_inst['id'])
    return("")

def add_isilon_shares(rubrik, host, protocol, add_list, az_list, export_id_list, nas_host_data, config):
    configuration = isi_sdk_8_0.Configuration()
    configuration.host = "https://" + host + ":8080"
    configuration.username = config['array_user']
    configuration.password = config['array_password']
    configuration.verify_ssl = False
    isilon = isi_sdk_8_0.ApiClient(configuration)
    isilon_protocols = isi_sdk_8_0.ProtocolsApi(isilon)
    dprint("Add_LIST: " + str(add_list))
    if protocol == "nfs":
        addr_list = []
        rubrik_net = rubrik.get('internal', '/cluster/me/network_interface', timeout=60)
        for n in rubrik_net['data']:
            for i in n['ipAddresses']:
                addr_list.append(i)
        rubrik_net = rubrik.get('internal', '/cluster/me/floating_ip', timeout=60)
        for f in rubrik_net['data']:
            if f['ip'] in addr_list:
                addr_list.remove(f['ip'])
    for nas_host in add_list:
        zone = get_zone_from_name(nas_host, az_list)
        host_id = get_hostid_from_nas_data(nas_host, nas_host_data)
        skipped_shares = []
        for share in add_list[nas_host]:
            if protocol == "smb":
                rf = config['smb_user'].split('@')
                rf2 = rf[1].split('.')
                user = rf2[0] + "\\" + rf[0]
                if zone != "System" or FORCE_SMB_ACL:
                    share_results = isilon_protocols.get_smb_share(share, zone=zone)
                    add_rar = True
                    for sh_data in share_results.shares:
                        for rar in sh_data.run_as_root:
                            if rar.type == "user" and rar.name.lower() == user.lower():
                                add_rar = False
                                break
                        if add_rar:
                            dprint("Adding rar to " + share)
                            new_rar_data = {'type': 'user', 'name': user}
                            sh_data.run_as_root.append(new_rar_data)
                            new_rar = {'run_as_root': sh_data.run_as_root}
                            share_update = isilon_protocols.update_smb_share(new_rar, share, zone=zone)
                            fix_perms = {'permissions': sh_data.permissions}
                            share_udpate = isilon_protocols.update_smb_share(fix_perms, share, zone=zone)
#                payload = {'hostId': host_id, 'shareType': protocol.upper(), 'exportPoint': share, 'user': rf[0], 'password': config['smb_password'], 'domain': rf[1]}
            elif protocol == "nfs":
                print("Adding Export: " + nas_host + ":" + share)
                export_info = isilon_protocols.get_nfs_export(export_id_list[share], zone=zone)
                dprint ("ROOT_MAP: " + str(export_info.exports[0].map_root.user.id))
                if export_info.exports[0].map_root.user.id != "USER:root" and export_info.exports[0].map_root.user.id != "UID:0":
                    root_clients = export_info.exports[0].root_clients
                    nfs_rc_add_list = []
                    for rubrik_ip in addr_list:
                        found = False
                        add_ips_to_export = False
                        for rc in root_clients:
                            if '/' in rc:
                                subnet = ipaddress.ip_network(unicode(rc))
                                node_ip = ipaddress.ip_address(unicode(rubrik_ip))
                                if node_ip in subnet:
                                    found = True
                                    break
                            else:
                                if rubrik_ip == rc:
                                    found = True
                                    break
                            if not found:
                                root_clients.append(rubrik_ip)
                                add_ips_to_export = True
                        if add_ips_to_export:
                            rc_update = {'root_clients': root_clients}
                            dprint (rc_update)
                            try:
                                update_exports = isilon_protocols.update_nfs_export(rc_update, export_id_list[share], ignore_unresolvable_hosts=True, ignore_bad_paths=True, zone=zone)
                            except ApiException as e:
                                sys.stderr.write("Exception calling update_nfs_export: " + str(e))
            payload = {'hostId': host_id, 'shareType': protocol.upper(), 'exportPoint': share}
            dprint("PAYLOAD: " + str(payload))
            try:
                share_id = rubrik.post('internal', '/host/share', payload, timeout=60)['id']
            except rubrik_cdm.exceptions.APICallException as e:
                sys.stderr.write("Share add failed: " + str(e) + "\n")
                skipped_shares.append(share)
        if skipped_shares:
            print("Failed Shares on " + nas_host + ": " + str(skipped_shares))

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
        if str(cfg_data['force_smb_acl']).lower() == "false" and FORCE_SMB_ACL:
            cfg_data['force_smb_acl'] = True
    except KeyError:
        pass
    return(cfg_data)

if __name__ == "__main__":
    az_list = []
    share_list = {}
    rubrik_share_list = {}
    export_list = {}
    rubrik_export_list = {}
    config = {}
    VERBOSE = False
    DEBUG = False
    REPORT_ONLY = False
    FORCE_SMB_ACL = False
    CHANGELIST = False
    nfs = True
    smb = True
    rbk_nas_hosts = ()


    optlist, args = getopt.getopt(sys.argv[1:], 'hc:vDz:rp:F', ['--help', '--config=', '--verbose', '--DEBUG', '--zones=', '--report', '--protocol=', '--force-acl'])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-c', '--config'):
            config = get_config_from_file(a)
        if opt in ('-v', '--verbose'):
            VERBOSE = True
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
            VERBOSE = True
        if opt in ('-z', '--zones'):
            az_list = a.split(',')
        if opt in ('-r', '--report'):
            REPORT_ONLY = True
        if opt in ('-p', '--protocol'):
            if a == "nfs":
                smb = False
            if a == "smb":
                nfs = False
        if opt in ('-F', '--force_acl'):
            FORCE_SMB_ACL = True
    try:
        (isilon_host, rubrik_host) = args
    except ValueError:
        usage()
    dprint("CONFIG: " + str(config))
    try:
        FORCE_SMB_ACL = bool(config['force_smb_acl'])
    except KeyError:
        pass
    dprint("FORCE_ACL: " + str(FORCE_SMB_ACL))
    if config['rubrik_user'] == "":
        config['rubrik_user'] = python_input("Rubrik User: ")
    if config['rubrik_password'] == "":
        config['rubrik_password'] = getpass.getpass("Rubrik Password: ")
    if config['array_user'] == "":
        config['array_user'] = python_input("Isilon User: ")
    if config['array_password'] == "":
        config['array_password'] = getpass.getpass("Isilon Password: ")

    rubrik = rubrik_cdm.Connect (rubrik_host, config['rubrik_user'], config['rubrik_password'])
#    print(nas_host_data)
    az_list = isln_get_share_list(isilon_host, config['array_user'], config['array_password'], '', True, az_list, config)
    missing_hosts = find_missing_hosts(rubrik, az_list, config)
    if missing_hosts:
        print ("Missing Hosts: " + str(missing_hosts))
        if not REPORT_ONLY:
            add_isilon_host(rubrik, missing_hosts, config)
    nas_host_data = rubrik.get('v1', '/host?operating_system_type=NONE')
    hs_data = rubrik.get('internal', '/host/share')
    if smb:
        (share_list, export_id_list) = isln_get_share_list(isilon_host, config['array_user'], config['array_password'], 'smb', False, az_list, config)
        rubrik_share_list = get_rubrik_share_list('SMB', az_list, hs_data)
        smb_add_list = list_compare(share_list, rubrik_share_list, config)
        print("Shares to add: " + str(smb_add_list))
        if not REPORT_ONLY:
            add_isilon_shares(rubrik, isilon_host, 'smb', smb_add_list, az_list, export_id_list, nas_host_data, config)
    if nfs:
        (export_list, export_id_list) = isln_get_share_list(isilon_host, config['array_user'], config['array_password'], 'nfs', False, az_list, config)
        rubrik_export_list = get_rubrik_share_list('NFS', az_list, hs_data)
        nfs_add_list = list_compare(export_list, rubrik_export_list, config)
        print ("Exports to add: " + str(nfs_add_list))
        if not REPORT_ONLY:
            add_isilon_shares(rubrik, isilon_host, 'nfs', nfs_add_list, az_list, export_id_list, nas_host_data, config)
