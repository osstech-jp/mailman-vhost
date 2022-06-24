import sys
import re
import ldap
import ldap.filter

from Mailman import mm_cfg
from Mailman import Utils
from Mailman.SafeDict import SafeDict
from Mailman.Logging.Syslog import syslog


def _conf_get(list_name):
    confs = mm_cfg.LDAP_AUTH
    return confs.get(list_name, confs.get('*'))


def _log(pri, fmt, *args):
    syslog(pri, 'LDAP Auth: ' + fmt % args)


def _auth(conf, listname, listdomain, username, password):
    if username is None or len(username) == 0:
        return (None, None)

    d = SafeDict({
            'list_name':    listname,
            'list_domain':  listdomain,
            'list_email':   listname + '@' + listdomain,
            'auth_id':      username,
        })
    try:
        d['auth_id_local'], d['auth_id_domain'] = re.split('@', username, 1)
    except ValueError:
        d['auth_id_local'] = username
        d['auth_id_domain'] = ''

    uri = ' '.join(conf.get('uris', ['ldap://127.0.0.1/']))
    bind_dn = conf.get('bind_dn', '')
    bind_pw = conf.get('bind_password', '')
    search_base = conf.get('search_base', None)
    search_filter = conf.get('search_filter', '(mail=%(auth_id)s)') % {
        k: ldap.filter.escape_filter_chars(v) for k, v in d.items()
        }
    attrs = conf.get('attributes', [])
    result_fmt = conf.get('result_format', '%(auth_id)s')

    if search_base == None:
        _log('error', 'Base DN not defined')
        return (None, None)

    c = ldap.initialize(uri, trace_level=mm_cfg.LDAP_AUTH_TRACE_LEVEL, trace_file=sys.stderr)
    try:
        c.bind_s(bind_dn, bind_pw, ldap.AUTH_SIMPLE)
    except (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.UNWILLING_TO_PERFORM), e:
        _log('error', 'URI %s: %s', uri, e)
        return (None, None)
    except ldap.INVALID_CREDENTIALS, e:
        _log('error', 'Bind DN %s: %s', bind_dn, e)
        return (None, None)

    ## Search for an auth_id's entry
    try:
        try:
            entries = c.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter, attrs)
        except (ldap.INVALID_DN_SYNTAX, ldap.NO_SUCH_OBJECT), e:
            _log('error', 'Base DN %s: %s', search_base, e)
            return (None, None)
        except ldap.FILTER_ERROR, e:
            _log('error', 'Filter %s: %s', search_filter, e)
            return (None, None)
    finally:
        c.unbind_s()

    if len(entries) == 0:
        ## No such entry
        return (None, None)
    if len(entries) > 1:
        _log('error', 'Multiple entries found for user %s', username)
        return (None, None)

    dn, attrs = entries[0]
    d.update({ k: i[0] for k, i in attrs.items() })
    result = result_fmt % d
    if password is None:
        return (result, dn)

    ## Bind with the auth_id's DN and password to authenticate the auth_id
    c = ldap.initialize(uri, trace_level=mm_cfg.LDAP_AUTH_TRACE_LEVEL, trace_file=sys.stderr)
    try:
        try:
            c.bind_s(dn, password, ldap.AUTH_SIMPLE)
        except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM):
            return (None, dn)
    finally:
        c.unbind_s()

    return (result, dn)


def ldap_auth_enabled_p():
    """
    Check if the LDAP authentication is enabled.
    """
    return len(mm_cfg.LDAP_AUTH) > 0


def ldap_auth_only_p():
    """
    Check if only the LDAP authentication is enabled.
    """
    return mm_cfg.LDAP_AUTH_ONLY


def ldap_auth_context(authcontexts, listname, listdomain, username, password, mlist=None):
    """
    Authenticate a user with a password by LDAP

    Returns
    -------
    ac: int
        Mailman authentication context or None if no LDAP auth performed or LDAP auth failed.
    result: str
        Result username formatted with ldap_conf['result_format'] and attributes.
    """
    ldap_conf = _conf_get(listname)
    if not ldap_conf:
        return (None, None)

    result, dn = _auth(ldap_conf, listname, listdomain, username, password)
    if result is None:
        if ldap_auth_only_p():
            return (mm_cfg.UnAuthorized, None)
        return (None, None)

    ## Check if the authenticated user is in admin or member lists
    for ac in authcontexts:
        if ac == mm_cfg.AuthSiteAdmin:
            if Utils.addr_in_list_p(result, mm_cfg.LDAP_AUTH_SITE_ADMINS):
                return (ac, result)
        elif ac == mm_cfg.AuthCreator:
            if Utils.addr_in_list_p(result, mm_cfg.LDAP_AUTH_LIST_CREATORS):
                return (ac, result)
        elif ac == mm_cfg.AuthListAdmin:
            if mlist and Utils.addr_in_list_p(result, mlist.owner):
                return (ac, result)
        elif ac == mm_cfg.AuthListModerator:
            if mlist and Utils.addr_in_list_p(result, mlist.moderator):
                return (ac, result)
            if Utils.addr_in_list_p(result, mm_cfg.LDAP_AUTH_SITE_MODERATORS):
                return (ac, result)
        elif ac == mm_cfg.AuthListPoster:
            continue ## FIXME: Not supproted yet
        elif ac == mm_cfg.AuthUser:
            if mlist and result.lower() in mlist.members:
                return (ac, result)
        else:
            ## What is this context???
            _log('error', 'Bad authcontext: %s', ac)
            raise ValueError, 'Bad authcontext: %s' % ac

    return (mm_cfg.UnAuthorized, result)


def ldap_auth_member(mlist, member, password):
    """
    Authenticate a member. (obsolete)
    Use ldap_auth_context() instead.
    """
    confs = mm_cfg.MEMBER_LDAP_AUTH
    if mlist.internal_name() in confs:
        conf = confs[mlist.internal_name()]
    elif '*' in confs:
        conf = confs['*']
    else:
        return 0

    d = SafeDict({'list_name':	mlist.internal_name(),
                'list_address':	mlist.GetListEmail(),
                'list_domain':	mlist.host_name,
                'member_address':	member,
                })
    try:
        d['member_local'], d['member_domain'] = re.split('@', member, 1)
    except ValueError:
        d['member_local'] = member_address
        d['member_domain'] = ''

    uri = ' '.join(conf.get('uris', conf.get('uri', ['ldap://127.0.0.1/'])))
    bind_dn = conf.get('bind_dn', '')
    bind_pw = conf.get('bind_password', '')
    search_base = conf.get('base', None)
    search_filter = conf.get('filter', '(uid=%(member_local)s)') % {
        k: ldap.filter.escape_filter_chars(v) for k, v in d.items()
        }

    if search_base == None:
        _log('error', 'Base DN not defined')
        return 0

    c = ldap.initialize(uri, trace_level=mm_cfg.LDAP_AUTH_TRACE_LEVEL, trace_file=sys.stderr)
    try:
        c.bind_s(bind_dn, bind_pw, ldap.AUTH_SIMPLE)
    except (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.UNWILLING_TO_PERFORM), e:
        _log('error', 'URI %s: %s', uri, e)
        return (None, None)
    except ldap.INVALID_CREDENTIALS, e:
        _log('error', 'Bind DN %s: %s', bind_dn, e)
        return (None, None)

    ## Search for the member's entry
    try:
        try:
            entries = c.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter, ['dn'])
        except (ldap.INVALID_DN_SYNTAX, ldap.NO_SUCH_OBJECT), e:
            _log('error', 'Base DN %s: %s', search_base, e)
            return 0
        except ldap.FILTER_ERROR, e:
            _log('error', 'Filter %s: %s', search_filter, e)
            return 0
    finally:
        c.unbind_s()

    if len(entries) == 0:
        return 0
    if len(entries) > 1:
        _log('error', 'Multiple entries found for user %s', username)
        return 0

    dn, attrs = entries[0]

    ## Bind with the auth_id's DN and password to authenticate the auth_id
    c = ldap.initialize(uri, trace_level=mm_cfg.LDAP_AUTH_TRACE_LEVEL, trace_file=sys.stderr)
    try:
        try:
            c.bind_s(dn, password, ldap.AUTH_SIMPLE)
        except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM):
            return 0
    finally:
        c.unbind_s()

    return dn
