#/bin/sh
find lib -name '*.pm' | while read i; do perl -cwIlib $i; done
find bin/{gateway,admintool} cgi-bin -perm +0111 -type f | \
    while read i; do perl -cwIlib $i; done
