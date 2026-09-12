#!/bin/sh

# Consume at most 4096 bytes so fuzz inputs cannot make the helper allocate
# unbounded memory.  EOF also terminates this read for shorter request bodies.
dd bs=1 count=4096 of=/dev/null 2>/dev/null

case "${QUERY_STRING:-normal}" in
status)
    printf 'Status: 201 Created\r\nContent-Type: text/plain\r\n\r\ncgi-status\n'
    ;;
redirect)
    printf 'Location: /files/index.txt\r\n\r\n'
    ;;
xsendfile)
    printf 'X-Sendfile: %s\r\n\r\n' "${FUZZ_X_SENDFILE:-${DOCUMENT_ROOT}/files/index.txt}"
    ;;
stream)
    printf 'Content-Type: text/plain\r\n\r\ncgi-stream-a\ncgi-stream-b\n'
    ;;
*)
    printf 'Content-Type: text/plain\r\nX-CGI-Method: %s\r\n\r\ncgi-ok\n' "${REQUEST_METHOD:-UNKNOWN}"
    ;;
esac
