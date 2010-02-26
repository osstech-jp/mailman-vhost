# Copyright (C) 2002-2010 by the Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software 
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

"""Provide some customization for site-wide behavior.

This should be considered experimental for Mailman 2.1.  The default
implementation should work for standard Mailman.
"""

import os
import errno
import sys

from Mailman import mm_cfg

try:
    True, False
except NameError:
    True = 1
    False = 0



def _makedir(path):
    try:
        omask = os.umask(0)
        try:
            os.makedirs(path, 02775)
        finally:
            os.umask(omask)
    except OSError, e:
        # Ignore the exceptions if the directory already exists
        if e.errno <> errno.EEXIST:
            raise



def get_listsubdir(listname):
    """Return subdirectory name for the named list.

    Append this subdirectory name to a subsystem specific directory
    such as archives/private/ or similar.

    The directory scheme implemented is like this:
    
        <subsystem directory>/
           mylist0/            # one "site default list"
           mylist1/            # another "site default list"
           some.domain.com/
              mylist1/         # a "vhost list"
              mylist2/         # another "vhost list"
           mydomain.com/
              mylist1/         # yet another "vhost list"

    Ideally, this function and get_listnames() below would be the only
    code to modify if you want to introduce another disk storage
    scheme, e.g. d/domain.com/mylist1 and m/mydomain.com/mylist1.
    
    See also get_listpath and get_archpath docs for example usage.
    """
    if '@' in listname:
        tmp = listname.split('@')
        return os.path.join(tmp[1],tmp[0])
    else:
        return listname
    
    

def get_listpath(listname, create=0):
    """Return the file system path to the list directory for the named list.

    If the create flag is true, then this method should create the path
    hierarchy if necessary.  If the create flag is false, then this function
    should not attempt to create the path heirarchy (and in fact the absence
    of the path might be significant).
    """
    path = os.path.join(mm_cfg.LIST_DATA_DIR,
                        get_listsubdir(listname))
    if create:
        _makedir(path)
    return path



def get_archpath(listname, create=False, public=False):
    """Return the file system path to the list's archive directory for the
    named list in the named virtual domain.

    If the create flag is true, then this method should create the path
    hierarchy if necessary.  If the create flag is false, then this function
    should not attempt to create the path heirarchy (and in fact the absence
    of the path might be significant).

    If public is true, then the path points to the public archive path (which
    is usually a symlink instead of a directory).
    """
    if public:
        subdir = mm_cfg.PUBLIC_ARCHIVE_FILE_DIR
    else:
        subdir = mm_cfg.PRIVATE_ARCHIVE_FILE_DIR
    path = os.path.join(subdir, get_listsubdir(listname))
    if create:
        _makedir(path)
    return path



def get_mboxpath(listname, create=False, public=False):
    """Get path to archive mbox file"""
    # Pass public. Don't pass create as it won't do the right thing.
    return os.path.join(get_archpath(listname, public=public) + '.mbox',
                        listname.split('@')[0] + '.mbox')



def get_listnames(domain=None):
    """Return the names of all the known lists for the given domain.

    If domain is given, it is the virtual domain for the named list.  The
    default is to not distinguish list paths on the basis of virtual domains.
    """
    # Import this here to avoid circular imports
    from Mailman.Utils import list_exists
    got = []
    datadir = mm_cfg.LIST_DATA_DIR
    if domain:
        domaindir = os.path.join(datadir, domain)
        if os.path.isdir(domaindir):
            for localpart in os.listdir(domaindir):
                listname = '@'.join([localpart, domain])
                if list_exists(listname):
                    got.append(listname)
    else:
        for fn in os.listdir(datadir):
            if list_exists(fn):
                got.append(fn)
            else:
                got.extend(get_listnames(fn))
    return got
