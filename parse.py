#!/usr/bin/python3

# parse output from Nessus plugin 60119 / Samba share enumeration

# (c) 2020 Roey Katz, published under the terms of the GPL3 license or newer

# Use the following syntax for this script:
#
#   python3 parse.py INPUT-FILE OUTPUT-FILE
#
# where INPUT-FILE is the file containing the contents of the 60119 plugin's output,
# and OUTPUT-FILE is the name you want for the the output from this
# script, in comma-separated-value (CSV) format.

# the latest copy of this script can always be found at:
# https://github.com/roeyk/nessus_plugin_60119    



import sys,typing
from dataclasses import dataclass

if len(sys.argv) != 3:
    print("syntax: python3 parse.py <input_filename> <output_filename>")
    sys.exit(1)

filename = sys.argv[1]


@dataclass
class Line:
    local_path: str=""
    share_path: str=""
    share_folder: str=""
    users: str=""
    users_hash: str=""
    perm_read: str=""
    perm_write: str=""
    perm_exec: str=""
    comment: str=""
    ip: str=""
    mac: str=""
    dnsname: str=""
    netbios_name: str=""

cur_path = cur_comment = cur_share_path = cur_share_folder = cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""
ip = mac = dnsname = netbios_name = ""    

database = []


for _line in open(sys.argv[1]):
    
    line = _line.strip()
    if line.startswith("\"Plugin"): continue   # skip past first header line

    # start a new host
    if line.startswith("\"60119"):
        # zero-out any previous comment
        cur_comment = ""
        
        # parse out the IP, MAC and netbios_name        
        values = line.split(',')
        ip, mac, dnsname, netbios_name = values[4], values[9], values[10], values[11]

    # start a new path
    if line.startswith("Local path :"):
        # add cur_path
        cur_local_path = line.split("Local path :")[1].strip()
        
    elif line.startswith("Share path : "):
        # add cur_share_path
        cur_share_path = line.split("Share path :")[1].strip()
        cur_share_folder = cur_share_path.split('\\')[-1]

    elif line.startswith("Comment : "):
        # add cur_comment
        cur_comment = line.split("Comment :")[1].strip()


    elif line.startswith("[*] Allow ACE for "):
        # add cur_users
        __cur_users = line.split("[*] Allow ACE for ")[1]
        _cur_users, __cur_users_hash = _cur_users.split(':')
        cur_users = _cur_users.strip()
        cur_users_hash =  _cur_users_hash.strip()

    elif line.startswith("FILE_GENERIC_READ"):
        # add cur perms
        cur_perm_read=line.split("FILE_GENERIC_READ:")[1].strip()

    elif line.startswith("FILE_GENERIC_WRITE"):
        # add cur perms
        cur_perm_write=line.split("FILE_GENERIC_WRITE:")[1].strip()
        
    elif line.startswith("FILE_GENERIC_EXECUTE"):
        # add cur perms
        cur_perm_exec={"YE":"YES","NO":"NO"}[line.split("FILE_GENERIC_EXECUTE:")[1].strip()[:2]]

        # at this point we've reached the end of the lines for any one entry, so add the Line entity to the database
        # flush out whatever remaining data we had from the previous lines..
        ent = Line(cur_local_path, cur_share_path, cur_share_folder, cur_users, cur_users_hash, cur_perm_read, cur_perm_write, cur_perm_exec, cur_comment, ip, mac, dnsname, netbios_name)
        database.append(ent)

        # zero-out the old info, retaining the current path, share path and comment
        cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""

output_file = open(sys.argv[2], 'w')

# write header
header = "IP,MAC,DNS Name,NetBIOS Name,Local Path,Share Path,Share Folder,Users,Users Hash,READ,WRITE,EXECUTE,Comment\n"
output_file.write(header)

for ent in database:
    output_line = f'{ent.ip}, {ent.mac}, {ent.dnsname}, {ent.netbios_name}, {ent.local_path},"{ent.share_path}","{ent.share_folder}","{ent.users}","{ent.users_hash}","{ent.perm_read}","{ent.perm_write}","{ent.perm_exec}","{ent.comment}"\n'
    output_file.write(output_line)





