#!/bin/sh
# RESTler token_refresh_command: metadata line, then one header line per user.
# User 1 (alpha-admin) is RESTler's main user; user 2 (bravo-admin) is the NamespaceRule attacker.
echo "{u'alpha-admin': {}, u'bravo-admin': {}}"
echo "Authorization: Bearer tok-alpha-admin"
echo "Authorization: Bearer tok-bravo-admin"
