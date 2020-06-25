#!/usr/bin/python3

# parse Nessus plugin 60119 output

# (c) 2020 Roey Katz, published under the terms of the GPL3 license or newer

import sys,typing
from dataclasses import dataclass

if len(sys.argv)==1:
    print("syntax: python3 parse.py <filename>")
    sys.exit(1)

filename = sys.argv[1]



@dataclass
class Line:
    path: str=""
    users: str=""
    users_hash: str=""
    perm_read: str=""
    perm_write: str=""
    perm_exec: str=""

cur_path = cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""    
database = []
    


for _line in open(sys.argv[1]):    
    
    line = _line.strip()

    # start a new path..
    if line.startswith("Local path :"):
        # add cur_path
        cur_path = line.split("Local path :")[1].strip()
#        print(f'cur_path={cur_path}')
        
    elif line.startswith("[*] Allow ACE for "):
        # add cur_users
        _cur_users = line.split("[*] Allow ACE for ")[1]
        cur_users, cur_users_hash = _cur_users.split(' ')
        cur_users = cur_users[:-1]
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
        ent = Line(cur_path, cur_users, cur_users_hash, cur_perm_read, cur_perm_write, cur_perm_exec)
        database.append(ent)
#        print(f'added new entity: {ent}')
          
        # zero-out the old info, retaining the current path
        cur_users = cur_perm_read = cur_perm_write = cur_perm_exec = ""
        
for l in database:
    print(l)
