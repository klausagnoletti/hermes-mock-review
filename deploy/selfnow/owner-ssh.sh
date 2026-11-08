#!/bin/sh
# Forced command for the dedicated owner ssh key. In authorized_keys:
#   restrict,command="/path/to/owner-ssh.sh" ssh-ed25519 AAAA... mock-review-owner
# ssh puts what the client asked for in SSH_ORIGINAL_COMMAND. Exactly four request forms are accepted:
#   PUT    /publish/<slug>                       body: a tar archive on stdin
#   PATCH  /publish/<slug>/metadata              body: JSON on stdin
#   DELETE /publish/<slug>
#   GET    /publishes/<slug>/data/feedback[?limit=N&cursor=ID]
# Everything else exits 2 before any request is made. The request goes to the owner listener on host loopback
# (SELFNOW_OWNER_URL, default http://127.0.0.1:8081). The response body is printed, then a final line "STATUS <code>".
set -eu

base="${SELFNOW_OWNER_URL:-http://127.0.0.1:8081}"
cmd="${SSH_ORIGINAL_COMMAND-}"

deny() {
    echo "refused" >&2
    exit 2
}

[ -n "$cmd" ] || deny
# One line of printable ASCII: no newline, no control character, nothing non-ASCII.
case "$cmd" in
    *'
'*) deny ;;
esac
if printf '%s' "$cmd" | LC_ALL=C grep -q '[^ -~]'; then
    deny
fi

method="${cmd%% *}"
path="${cmd#* }"
[ "$method $path" = "$cmd" ] || deny

slug='[a-z0-9][a-z0-9-]{1,80}'
matches() {
    printf '%s' "$path" | grep -Eq "^$1\$"
}

case "$method" in
    PUT)
        matches "/publish/$slug" || deny
        ctype='application/octet-stream'
        has_body=yes
        ;;
    PATCH)
        matches "/publish/$slug/metadata" || deny
        ctype='application/json'
        has_body=yes
        ;;
    DELETE)
        matches "/publish/$slug" || deny
        has_body=no
        ;;
    GET)
        matches "/publishes/$slug/data/feedback(\?[A-Za-z0-9=&]{0,200})?" || deny
        has_body=no
        ;;
    *)
        deny
        ;;
esac

if [ "$has_body" = yes ]; then
    exec curl -sS --max-time 300 -X "$method" -H "Content-Type: $ctype" --data-binary @- \
        -w '\nSTATUS %{http_code}\n' "$base$path"
fi
exec curl -sS --max-time 60 -X "$method" -w '\nSTATUS %{http_code}\n' "$base$path"
