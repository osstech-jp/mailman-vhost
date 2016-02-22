# Copyright (C) 2001-2014 by the Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

"""Creation/deletion hooks for the Postfix MTA."""

import os
import pwd
import grp
import time
import errno
from stat import *

from Mailman import mm_cfg
from Mailman import Utils
from Mailman import LockFile
from Mailman.i18n import C_
from Mailman.MTA.Utils import makealiases
from Mailman.Logging.Syslog import syslog

LOCKFILE = os.path.join(mm_cfg.LOCK_DIR, 'creator')
ALIASFILE = os.path.join(mm_cfg.DATA_DIR, 'aliases')
VIRTFILE = os.path.join(mm_cfg.DATA_DIR, 'virtual-mailman')

try:
    True, False
except NameError:
    True = 1
    False = 0



def _update_maps():
    msg = 'command failed: %s (status: %s, %s)'
    acmd = mm_cfg.POSTFIX_ALIAS_CMD + ' ' + ALIASFILE
    status = (os.system(acmd) >> 8) & 0xff
    if status:
        errstr = os.strerror(status)
        syslog('error', msg, acmd, status, errstr)
        raise RuntimeError, msg % (acmd, status, errstr)
    if os.path.exists(VIRTFILE):
        vcmd = mm_cfg.POSTFIX_MAP_CMD + ' ' + VIRTFILE
        status = (os.system(vcmd) >> 8) & 0xff
        if status:
            errstr = os.strerror(status)
            syslog('error', msg, vcmd, status, errstr)
            raise RuntimeError, msg % (vcmd, status, errstr)



def makelock():
    return LockFile.LockFile(LOCKFILE)


def _zapfile(filename):
    # Truncate the file w/o messing with the file permissions, but only if it
    # already exists.
    if os.path.exists(filename):
        fp = open(filename, 'w')
        fp.close()


def clear():
    _zapfile(ALIASFILE)
    _zapfile(VIRTFILE)



def _addlist(mlist, fp):
    # Set up the mailman-loop address
    loopaddr = Utils.ParseEmail(Utils.get_site_email(extra='loop'))[0]
    loopmbox = os.path.join(mm_cfg.DATA_DIR, 'owner-bounces.mbox')
    # Seek to the end of the text file, but if it's empty write the standard
    # disclaimer, and the loop catch address.
    fp.seek(0, 2)
    if not fp.tell():
        print >> fp, """\
# This file is generated by Mailman, and is kept in sync with the
# binary hash file aliases.db.  YOU SHOULD NOT MANUALLY EDIT THIS FILE
# unless you know what you're doing, and can keep the two files properly
# in sync.  If you screw it up, you're on your own.
"""
        print >> fp, '# The ultimate loop stopper address'
        print >> fp, '%s: %s' % (loopaddr, loopmbox)
        print >> fp
    # Bootstrapping.  bin/genaliases must be run before any lists are created,
    # but if no lists exist yet then mlist is None.  The whole point of the
    # exercise is to get the minimal aliases.db file into existance.
    if mlist is None:
        return
    listname = mlist.internal_name()
    fieldsz = len(listname) + len('-unsubscribe')
    # The text file entries get a little extra info
    print >> fp, '# STANZA START:', listname
    print >> fp, '# CREATED:', time.ctime(time.time())
    # Now add all the standard alias entries
    for k, v in makealiases(listname):
        # Format the text file nicely
        print >> fp, k + ':', ((fieldsz - len(k)) * ' ') + v
    # Finish the text file stanza
    print >> fp, '# STANZA END:', listname
    print >> fp



def _isvirtual(mlist):
    return (mlist and mlist.host_name.lower() in
            [d.lower() for d in mm_cfg.POSTFIX_STYLE_VIRTUAL_DOMAINS])

def _addvirtual(mlist, fp):
    listname = mlist.internal_name()
    fieldsz = len(listname) + len('-unsubscribe')
    hostname = mlist.host_name
    # Set up the mailman-loop address
    loopaddr = Utils.get_site_email(mlist.host_name, extra='loop')
    loopdest = Utils.ParseEmail(loopaddr)[0]
    # And the site list posting address.
    siteaddr = Utils.get_site_email(mlist.host_name)
    sitedest = Utils.ParseEmail(siteaddr)[0]
    if mm_cfg.VIRTUAL_MAILMAN_LOCAL_DOMAIN:
        loopdest += '@' + mm_cfg.VIRTUAL_MAILMAN_LOCAL_DOMAIN
    # Seek to the end of the text file, but if it's empty write the standard
    # disclaimer, and the loop catch address and site address.
    fp.seek(0, 2)
    if not fp.tell():
        print >> fp, """\
# This file is generated by Mailman, and is kept in sync with the binary hash
# file virtual-mailman.db.  YOU SHOULD NOT MANUALLY EDIT THIS FILE unless you
# know what you're doing, and can keep the two files properly in sync.  If you
# screw it up, you're on your own.
#
# Note that you should already have this virtual domain set up properly in
# your Postfix installation.  See README.POSTFIX for details.

# LOOP ADDRESSES START
%s\t%s
# LOOP ADDRESSES END

# We also add the site list address in each virtual domain as that address
# is exposed on admin and listinfo overviews.
# SITE ADDRESSES START
%s\t%s
# SITE ADDRESSES END
""" % (loopaddr, loopdest, siteaddr, sitedest)
    # The text file entries get a little extra info
    print >> fp, '# STANZA START:', listname
    print >> fp, '# CREATED:', time.ctime(time.time())
    # Now add all the standard alias entries
    for k, v in makealiases(listname):
        fqdnaddr = '%s@%s' % (k, hostname)
        if mm_cfg.VIRTUAL_MAILMAN_LOCAL_DOMAIN:
            localaddr = '%s@%s' % (k, mm_cfg.VIRTUAL_MAILMAN_LOCAL_DOMAIN)
        else:
            localaddr = k
        # Format the text file nicely
        print >> fp, fqdnaddr, ((fieldsz - len(k)) * ' '), localaddr
    # Finish the text file stanza
    print >> fp, '# STANZA END:', listname
    print >> fp



# Blech.
def _check_for_virtual_loopaddr(mlist, filename):
    loopaddr = Utils.get_site_email(mlist.host_name, extra='loop')
    loopdest = Utils.ParseEmail(loopaddr)[0]
    siteaddr = Utils.get_site_email(mlist.host_name)
    sitedest = Utils.ParseEmail(siteaddr)[0]
    infp = open(filename)
    omask = os.umask(007)
    try:
        outfp = open(filename + '.tmp', 'w')
    finally:
        os.umask(omask)
    try:
        # Find the start of the loop address block
        while True:
            line = infp.readline()
            if not line:
                break
            outfp.write(line)
            if line.startswith('# LOOP ADDRESSES START'):
                break
        # Now see if our domain has already been written
        while True:
            line = infp.readline()
            if not line:
                break
            if line.startswith('# LOOP ADDRESSES END'):
                # It hasn't
                print >> outfp, '%s\t%s' % (loopaddr, loopdest)
                outfp.write(line)
                break
            elif line.startswith(loopaddr):
                # We just found it
                outfp.write(line)
                break
            else:
                # This isn't our loop address, so spit it out and continue
                outfp.write(line)
        # Now do it all again for the site list address. It must follow the
        # loop addresses.
        while True:
            line = infp.readline()
            if not line:
                break
            outfp.write(line)
            if line.startswith('# SITE ADDRESSES START'):
                break
        # Now see if our domain has already been written
        while True:
            line = infp.readline()
            if not line:
                break
            if line.startswith('# SITE ADDRESSES END'):
                # It hasn't
                print >> outfp, '%s\t%s' % (siteaddr, sitedest)
                outfp.write(line)
                break
            elif line.startswith(siteaddr):
                # We just found it
                outfp.write(line)
                break
            else:
                # This isn't our loop address, so spit it out and continue
                outfp.write(line)
        outfp.writelines(infp.readlines())
    finally:
        infp.close()
        outfp.close()
    os.rename(filename + '.tmp', filename)



def _do_create(mlist, textfile, func):
    # Crack open the plain text file
    try:
        fp = open(textfile, 'r+')
    except IOError, e:
        if e.errno <> errno.ENOENT: raise
        omask = os.umask(007)
        try:
            fp = open(textfile, 'w+')
        finally:
            os.umask(omask)
    try:
        func(mlist, fp)
    finally:
        fp.close()
    # Now double check the virtual plain text file
    if func is _addvirtual:
        _check_for_virtual_loopaddr(mlist, textfile)


def create(mlist, cgi=False, nolock=False, quiet=False):
    # Acquire the global list database lock.  quiet flag is ignored.
    lock = None
    if not nolock:
        lock = makelock()
        lock.lock()
    # Do the aliases file, which need to be done in any case
    try:
        _do_create(mlist, ALIASFILE, _addlist)
        if _isvirtual(mlist):
            _do_create(mlist, VIRTFILE, _addvirtual)
        # bin/genaliases is the only one that calls create with nolock = True.
        # Use that to only update the maps at the end of genaliases.
        if not nolock:
            _update_maps()
    finally:
        if lock:
            lock.unlock(unconditionally=True)



def _do_remove(mlist, textfile, virtualp):
    listname = mlist.internal_name()
    # Now do our best to filter out the proper stanza from the text file.
    # The text file better exist!
    outfp = None
    try:
        infp = open(textfile)
    except IOError, e:
        if e.errno <> errno.ENOENT: raise
        # Otherwise, there's no text file to filter so we're done.
        return
    try:
        omask = os.umask(007)
        try:
            outfp = open(textfile + '.tmp', 'w')
        finally:
            os.umask(omask)
        filteroutp = False
        start = '# STANZA START: ' + listname
        end = '# STANZA END: ' + listname
        oops = '# STANZA START: '
        while 1:
            line = infp.readline()
            if not line:
                break
            # If we're filtering out a stanza, just look for the end marker and
            # filter out everything in between.  If we're not in the middle of
            # filtering out a stanza, we're just looking for the proper begin
            # marker.
            if filteroutp:
                if line.strip() == end:
                    filteroutp = False
                    # Discard the trailing blank line, but don't worry if
                    # we're at the end of the file.
                    infp.readline()
                elif line.startswith(oops):
                    # Stanza end must be missing - start writing from here.
                    filteroutp = False
                    outfp.write(line)
                # Otherwise, ignore the line
            else:
                if line.strip() == start:
                    # Filter out this stanza
                    filteroutp = True
                else:
                    outfp.write(line)
    # Close up shop, and rotate the files
    finally:
        infp.close()
        outfp.close()
    os.rename(textfile+'.tmp', textfile)


def remove(mlist, cgi=False):
    # Acquire the global list database lock
    lock = makelock()
    lock.lock()
    try:
        _do_remove(mlist, ALIASFILE, False)
        if _isvirtual(mlist):
            _do_remove(mlist, VIRTFILE, True)
        # Regenerate the alias and map files
        _update_maps()
    finally:
        lock.unlock(unconditionally=True)



def checkperms(state):
    targetmode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
    for file in ALIASFILE, VIRTFILE:
        if state.VERBOSE:
            print C_('checking permissions on %(file)s')
        stat = None
        try:
            stat = os.stat(file)
        except OSError, e:
            if e.errno <> errno.ENOENT:
                raise
        if stat and (stat[ST_MODE] & targetmode) <> targetmode:
            state.ERRORS += 1
            octmode = oct(stat[ST_MODE])
            print C_('%(file)s permissions must be 066x (got %(octmode)s)'),
            if state.FIX:
                print C_('(fixing)')
                os.chmod(file, stat[ST_MODE] | targetmode)
            else:
                print
        # Make sure the corresponding .db files are owned by the Mailman user.
        # We don't need to check the group ownership of the file, since
        # check_perms checks this itself.
        dbfile = file + '.db'
        stat = None
        try:
            stat = os.stat(dbfile)
        except OSError, e:
            if e.errno <> errno.ENOENT:
                raise
            continue
        if state.VERBOSE:
            print C_('checking ownership of %(dbfile)s')
        user = mm_cfg.MAILMAN_USER
        ownerok = stat[ST_UID] == pwd.getpwnam(user)[2]
        if not ownerok:
            try:
                owner = pwd.getpwuid(stat[ST_UID])[0]
            except KeyError:
                owner = 'uid %d' % stat[ST_UID]
            print C_('%(dbfile)s owned by %(owner)s (must be owned by %(user)s'),
            state.ERRORS += 1
            if state.FIX:
                print C_('(fixing)')
                uid = pwd.getpwnam(user)[2]
                gid = grp.getgrnam(mm_cfg.MAILMAN_GROUP)[2]
                os.chown(dbfile, uid, gid)
            else:
                print
        if stat and (stat[ST_MODE] & targetmode) <> targetmode:
            state.ERRORS += 1
            octmode = oct(stat[ST_MODE])
            print C_('%(dbfile)s permissions must be 066x (got %(octmode)s)'),
            if state.FIX:
                print C_('(fixing)')
                os.chmod(dbfile, stat[ST_MODE] | targetmode)
            else:
                print
