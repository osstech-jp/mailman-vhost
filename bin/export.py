#! @PYTHON@
#
# Copyright (C) 2006 by the Free Software Foundation, Inc.
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

"""Export an XML representation of a mailing list."""

import sys
import datetime
import optparse

from xml.sax.saxutils import escape

import paths
from Mailman import Defaults
from Mailman import Errors
from Mailman import MemberAdaptor
from Mailman import Utils
from Mailman import mm_cfg
from Mailman.MailList import MailList
from Mailman.i18n import _

__i18n_templates__ = True

SPACE           = ' '
DOLLAR_STRINGS  = ('msg_header', 'msg_footer',
                   'digest_header', 'digest_footer',
                   'autoresponse_postings_text',
                   'autoresponse_admin_text',
                   'autoresponse_request_text')



class Indenter:
    def __init__(self, fp, indentwidth=4):
        self._fp     = fp
        self._indent = 0
        self._width  = indentwidth

    def indent(self):
        self._indent += 1

    def dedent(self):
        self._indent -= 1
        assert self._indent >= 0

    def write(self, s):
        self._fp.write(self._indent * self._width * ' ')
        self._fp.write(s)



class XMLDumper(object):
    def __init__(self, fp):
        self._fp        = Indenter(fp)
        self._tagbuffer = None
        self._stack     = []

    def _makeattrs(self, tagattrs):
        # The attribute values might contain angle brackets.  They might also
        # be None.
        attrs = []
        for k, v in tagattrs.items():
            if v is None:
                v = ''
            else:
                v = escape(str(v))
            attrs.append('%s="%s"' % (k, v))
        return SPACE.join(attrs)

    def _flush(self, more=True):
        if not self._tagbuffer:
            return
        name, attributes = self._tagbuffer
        self._tagbuffer = None
        if attributes:
            attrstr = ' ' + self._makeattrs(attributes)
        else:
            attrstr = ''
        if more:
            print >> self._fp, '<%s%s>' % (name, attrstr)
            self._fp.indent()
            self._stack.append(name)
        else:
            print >> self._fp, '<%s%s/>' % (name, attrstr)

    # Use this method when you know you have sub-elements.
    def _push_element(self, _name, **_tagattrs):
        self._flush()
        self._tagbuffer = (_name, _tagattrs)

    def _pop_element(self, _name):
        buffered = bool(self._tagbuffer)
        self._flush(more=False)
        if not buffered:
            name = self._stack.pop()
            assert name == _name, 'got: %s, expected: %s' % (_name, name)
            self._fp.dedent()
            print >> self._fp, '</%s>' % name

    # Use this method when you do not have sub-elements
    def _element(self, _name, _value=None, **_attributes):
        self._flush()
        if _attributes:
            attrs = ' ' + self._makeattrs(_attributes)
        else:
            attrs = ''
        if _value is None:
            print >> self._fp, '<%s%s/>' % (_name, attrs)
        else:
            # The value might contain angle brackets.
            value = escape(str(_value))
            print >> self._fp, '<%s%s>%s</%s>' % (_name, attrs, value, _name)

    def _do_list_categories(self, mlist, k, subcat=None):
        is_converted = bool(getattr(mlist, 'use_dollar_strings', False))
        info = mlist.GetConfigInfo(k, subcat)
        label, gui = mlist.GetConfigCategories()[k]
        if info is None:
            return
        for data in info[1:]:
            if not isinstance(data, tuple):
                continue
            varname = data[0]
            # Variable could be volatile
            if varname.startswith('_'):
                continue
            vtype = data[1]
            # Munge the value based on its type
            value = None
            if hasattr(gui, 'getValue'):
                value = gui.getValue(mlist, vtype, varname, data[2])
            if value is None:
                value = getattr(mlist, varname)
            # Do %-string to $-string conversions if the list hasn't already
            # been converted.
            if varname == 'use_dollar_strings':
                continue
            if not is_converted and varname in DOLLAR_STRINGS:
                value = Utils.to_dollar(value)
            if isinstance(value, list):
                self._push_element('option', name=varname)
                for v in value:
                    self._element('value', v)
                self._pop_element('option')
            else:
                self._element('option', value, name=varname)

    def _dump_list(self, mlist, with_passwords):
        # Write list configuration values
        self._push_element('list', name=mlist._internal_name)
        self._push_element('configuration')
        self._element('option',
                      mlist.preferred_language,
                      name='preferred_language')
        for k in mm_cfg.ADMIN_CATEGORIES:
            subcats = mlist.GetConfigSubCategories(k)
            if subcats is None:
                self._do_list_categories(mlist, k)
            else:
                for subcat in [t[0] for t in subcats]:
                    self._do_list_categories(mlist, k, subcat)
        self._pop_element('configuration')
        # Write membership
        self._push_element('roster')
        digesters = set(mlist.getDigestMemberKeys())
        for member in sorted(mlist.getMembers()):
            attrs = dict(id=member)
            cased = mlist.getMemberCPAddress(member)
            if cased <> member:
                attrs['original'] = cased
            self._push_element('member', **attrs)
            self._element('realname', mlist.getMemberName(member))
            if with_passwords:
                self._element('password', mlist.getMemberPassword(member))
            self._element('language', mlist.getMemberLanguage(member))
            # Delivery status, combined with the type of delivery
            attrs = {}
            status = mlist.getDeliveryStatus(member)
            if status == MemberAdaptor.ENABLED:
                attrs['status'] = 'enabled'
            else:
                attrs['status'] = 'disabled'
                attrs['reason'] = {MemberAdaptor.BYUSER    : 'byuser',
                                   MemberAdaptor.BYADMIN   : 'byadmin',
                                   MemberAdaptor.BYBOUNCE  : 'bybounce',
                                   }.get(mlist.getDeliveryStatus(member),
                                         'unknown')
            if member in digesters:
                if mlist.getMemberOption('plain'):
                    attrs['delivery'] = 'plain'
                else:
                    attrs['delivery'] = 'mime'
            else:
                attrs['delivery'] = 'regular'
            changed = mlist.getDeliveryStatusChangeTime(member)
            if changed:
                when = datetime.datetime.fromtimestamp(changed)
                attrs['changed'] = when.isoformat()
            self._element('delivery', **attrs)
            for option, flag in Defaults.OPTINFO.items():
                # Digest/Regular delivery flag must be handled separately
                if option in ('digest', 'plain'):
                    continue
                value = mlist.getMemberOption(member, flag)
                self._element(option, value)
            topics = mlist.getMemberTopics(member)
            if not topics:
                self._element('topics')
            else:
                self._push_element('topics')
                for topic in topics:
                    self._element('topic', topic)
                self._pop_element('topics')
            self._pop_element('member')
        self._pop_element('roster')
        self._pop_element('list')

    def dump(self, listnames, with_passwords=False):
        print >> self._fp, '<?xml version="1.0" encoding="UTF-8"?>'
        self._push_element('mailman', **{
            'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'xsi:noNamespaceSchemaLocation': 'ssi-1.0.xsd',
            })
        for listname in sorted(listnames):
            try:
                mlist = MailList(listname, lock=False)
            except Errors.MMUnknownListError:
                print >> sys.stderr, _('No such list: %(listname)s')
                continue
            self._dump_list(mlist, with_passwords)
        self._pop_element('mailman')

    def close(self):
        while self._stack:
            self._pop_element()



def parseargs():
    parser = optparse.OptionParser(version=mm_cfg.VERSION,
                                   usage=_("""\
%%prog [options]

Export the configuration and members of a mailing list in XML format."""))
    parser.add_option('-o', '--outputfile',
                      metavar='FILENAME', default=None, type='string',
                      help=_("""\
Output XML to FILENAME.  If not given, or if FILENAME is '-', standard out is
used."""))
    parser.add_option('-p', '--with-passwords',
                      default=False, action='store_true', help=_("""\
With this option, user passwords are included in cleartext.  For this reason,
the default is to not include passwords."""))
    parser.add_option('-l', '--listname',
                      default=[], action='append', type='string',
                      metavar='LISTNAME', dest='listnames', help=_("""\
The list to include in the output.  If not given, then all mailing lists are
included in the XML output.  Multiple -l flags may be given."""))
    opts, args = parser.parse_args()
    if args:
        parser.print_help()
        parser.error(_('Unexpected arguments'))
    return parser, opts, args



def main():
    parser, opts, args = parseargs()

    if opts.outputfile in (None, '-'):
        fp = sys.stdout
    else:
        fp = open(opts.outputfile, 'w')

    try:
        dumper = XMLDumper(fp)
        if opts.listnames:
            listnames = opts.listnames
        else:
            listnames = Utils.list_names()
        dumper.dump(listnames, opts.with_passwords)
        dumper.close()
    finally:
        if fp is not sys.stdout:
            fp.close()



if __name__ == '__main__':
    main()
