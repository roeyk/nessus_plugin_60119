#!/usr/bin/python3

# parse Nessus plugin 60119 output

# (c) 2020 Roey Katz, published under the terms of the GPL3 license or newer

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
    users: str=""
    users_hash: str=""
    perm_read: str=""
    perm_write: str=""
    perm_exec: str=""
    comment: str=""
    ip: str=""
    mac: str=""
    domain: str=""

cur_path = cur_comment = cur_share_path = cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""
ip = mac = domain = ""    

database = []



for _line in open(sys.argv[1]):
    
    line = _line.strip()
    if line.startswith("\"Plugin"): continue   # skip past header line
    

    # start a new host
    if line.startswith("\"60119"):
        # zero-out any previous comment
        cur_comment = ""
        
        
        # parse out the IP, MAC and domain        
        values = line.split(',')
        ip, mac, domain = values[4], values[9], values[11]

#        print(f'Found values:  IP: {IP}  MAC:  {MAC}  Domain: {DOMAIN}')

    # start a new path
    if line.startswith("Local path :"):
        # add cur_path
        cur_local_path = line.split("Local path :")[1].strip()
        
#        print(f'cur_local_path={cur_path}')

    elif line.startswith("Share path : "):
        # add cur_share_path
        cur_share_path = line.split("Share path :")[1].strip()
#        print(f'cur_share_path={cur_share_path}')

    elif line.startswith("Comment : "):
        # add cur_comment
        cur_comment = line.split("Comment :")[1].strip()


    elif line.startswith("[*] Allow ACE for "):
        # add cur_users
        _cur_users = line.split("[*] Allow ACE for ")[1]
#        print(f'_cur_users = "{_cur_users}"')
#        cur_users, cur_users_hash = _cur_users.split(' ')
        _cur_users, _cur_users_hash = _cur_users.split(':')
        cur_users = _cur_users.strip()
        cur_users_hash =  _cur_users_hash.strip()
#        print(f'cur_users={cur_users}')
#        print(f'cur_users_hash={cur_users_hash}')

    elif line.startswith("FILE_GENERIC_READ"):
        # add cur perms
        cur_perm_read=line.split("FILE_GENERIC_READ:")[1].strip()
#        print(f'starting FILE_GENERIC_READ: "{cur_perm_read}"')        

    elif line.startswith("FILE_GENERIC_WRITE"):
        # add cur perms
        cur_perm_write=line.split("FILE_GENERIC_WRITE:")[1].strip()
#        print(f'starting FILE_GENERIC_WRITE: "{cur_perm_write}"')        
        
    elif line.startswith("FILE_GENERIC_EXECUTE"):
        # add cur perms
        cur_perm_exec={"YE":"YES","NO":"NO"}[line.split("FILE_GENERIC_EXECUTE:")[1].strip()[:2]]
#        print(f'starting FILE_GENERIC_EXECUTE: "{cur_perm_exec}"')

        # at this point we've reached the end of the lines for any one entry, so add the Line entity to the database
        # flush out whatever remaining data we had from the previous lines..
        ent = Line(cur_local_path, cur_share_path, cur_users, cur_users_hash, cur_perm_read, cur_perm_write, cur_perm_exec, cur_comment, ip, mac, domain)
        database.append(ent)
#        print(f'added new entity: {ent}')

        # zero-out the old info, retaining the current path, share path and comment
        cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""

output_file = open(sys.argv[2], 'w')

# write header
header = "IP,MAC,Domain,Local Path,Share Path,Users,Users Hash,READ,WRITE,EXECUTE,Comment\n"
output_file.write(header)

for ent in database:
    output_line = f'{ent.ip}, {ent.mac}, {ent.domain}, {ent.local_path}","{ent.share_path}","{ent.users}","{ent.users_hash}","{ent.perm_read}","{ent.perm_write}","{ent.perm_exec}","{ent.comment}"\n'    
    output_file.write(output_line)





