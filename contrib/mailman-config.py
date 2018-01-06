#! @PYTHON@

# Show build-time configuration options
# This is free software under the GNU General Public License.
# Send bug reports or suggestions to Lindsay Haisley <fmouse@fmp.com>

print """Configuration and build information for Mailman\n"""

print "Mailman version: %s" % "@MM_VERSION@"
print "Build Date:      %s" % "@BUILD_DATE@"
print ""
print "prefix:          %s" % "@prefix@"
print "var_prefix:      %s" % "@VAR_PREFIX@"
print "mailman_user:    %s" % "@MAILMAN_USER@"
print "mailman_group:   %s" % "@MAILMAN_GROUP@"
print "mail_group:      %s" % "@MAIL_GROUP@"
print "cgi_group:       %s" % "@CGI_GROUP@"
print ""


print "configure_opts: \"%s\"" % "@CONFIGURE_OPTS@"

