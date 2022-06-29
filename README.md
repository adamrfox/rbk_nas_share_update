# rbk_nas_share_update
A project to automatically add shares from NTAP/Isilon to Rubrik for protection

The idea behind this project is to be able to automate adding shares to a Rubrik CDM system and automatically assign them to a fileset and backup policy.
Rubrik CDM has had the functionality to automatically add share from integrated NAS arrays since 5.3 but, as of now, filesets and SLA policies are still added manually.  However, through the use of APIs, it is possible to automate this process.

The challenge of this problem is one of standardization and exceptions.  It is quite common to not want to add certain shares at all, yet alone assign them to be backed up.  Also, it's difficult to know exeptions to SLA policies and fileset rules.  I have attempted to handle these to some extent via a configuration file where the user can define certain behaviors. 

The scrit comes in 3 flavors:  NTAP, Isilon, and Generic NFS.  I could do others (as well as a generic SMB) if there is interest out there.  Feel free to file issues here if you are interested.  The NTAP and NFS ones are very much up to date.  I haven't looked at the Isilon one in a while but can upon request and as time permits.  Reach out if you have that need as well.

The key to this project is the configuration file.  Each run requies a config file be specified by the user.  This file will set parameters needed for the script to properly run. Those parameters are defined here:

rubrik_user : If using a username/password to access the Rurbik cluster, define it here.  The script will prompt for it no auth is specified in the file. [GEN]

rubrik_password : If using username/password to access the Rurbik clsuter, define it here. The script will prompt for it if no auth is specified in the file. [GEN]

rubrik_token : If using token authentication, put the token here.  This is the required way if the cluster had TOTP enabled. [GEN]

array_user : This is the API user the script will for the array.  It can have the same privildges as the Rubrik cluster.  For NTAP, this is a cluster-level array user, for Isilon, this will be a root/admin account.  Note: could be different from the api_user depending on the NAS config.

array_password: This is the passoword for the above array user. 

array_scan: If true, the share will use an array-assisted scan (e.g. Isilon ChangeList, NTAP SnapDiff).  Note: CDM/array compatibility apply.

smb_user: This is the SMB user Rubrik will use for SMB shares.  This is used when adding new hosts/tenants (e.g. SVMs, Access Zones) to the Rubrik. [GEN]

smb_password: This is the SMB user password Rubrik will use for SMB shares.  This is used when adding new hosts/tenants (e.g. SVMs, Access Zones) to the Rubrik. [GEN]

api_user: This is the account Rubrik will use to access the API.  This could be different from array user.  For example, on NTAP user is to access the specific SVM. 

api_password: The is the password for the above api_user

nas_da: If set to true, this will set the NAS DA switch when adding the share to Rubrik

prefer_smb: If set to true, if the script finds the same path for NFS and SMB, it will only add the SMB share. [recommended]

exclude_path: Excludes any share that starts with a given list of paths (NFS or SMB).  The list is comma separated. [GEN]

exclude_share: Exclude any SMB share name in a given list of shares.  The list is comma separated.  [GEN]

exclude_host: Exclude any hosts in a given list of hosts.  The list is comma separated.  Examples are NTAP SVMs or Isilon Access Zones

default_nfs_fileset: Assigns specified fileset to any NFS export being added to the Rubrik by the script.

default_smb_fileset: Assigns specified fileset to any SMB share being added to the Rubrik by the script.

default_sla: Assigns specified SLA policy to any export or share being added to the Rubrik by the script. [GEN]

default_nfs_sla: Assigns specified SLA policy to any NFS export being added to the Rubrik by the script.  This over-rides default_sla for NFS exports.

default_smb_sla: Assigns specified SLA policy to any SMB share baing added to the Rubrik by the script.  This over-rides default_sla for SMB shares.

[GEN] denotes this option is supported by the generic scripts.



