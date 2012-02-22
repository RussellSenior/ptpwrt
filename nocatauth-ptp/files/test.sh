#/bin/sh
find lib -name '*.pm' | while read i; do perl -cwIlib $i; done
perl -cwIlib bin/gateway
