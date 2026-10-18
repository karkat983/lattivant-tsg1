#!/bin/sh
# RESTler token_refresh_command: metadata line, then one header line per user.
# User 1 (alpha-viewer) is RESTler's main user; user 2 (alpha-admin) is the NamespaceRule attacker.
echo "{u'alpha-viewer': {}, u'alpha-admin': {}}"
echo "Authorization: Bearer tok-alpha-viewer"
echo "Authorization: Bearer tok-alpha-admin"
