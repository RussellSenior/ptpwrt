### Install somewhere else if you've a mind (or aren't root).

PREFIX	    = /usr/local/nocat

### DESTDIR allows packagers to temporarily install somewhere else.

DESTDIR	    =

### Change WRAP_USER only if you want to use fw-wrap (the setuid wrapper) and
### want to run as a different user than 'nocat'.

WRAP_USER   = nocat

### These aren't the droids you're looking for.

INSTALL	    = cp -R
INST_BIN    = bin
INST_ETC    = etc
INST_GW	    = lib pgp
INST_FORMS  = htdocs
INST_SERV   = cgi-bin
TARGET      = $(DESTDIR)$(PREFIX)

all: install

install:
	@echo
	@echo "Nothing to build. Edit the Makefile to suit, then run 'make gateway'"
	@echo "'make suid-gateway', or 'make authserv'."
	@echo

$(TARGET): 
	[ -d $(TARGET) ] || mkdir -p $(TARGET)
	chmod 755 $(TARGET)

check_fw:
	@echo -n "Checking for firewall compatibility: "
	@bin/detect-fw.sh bin || ( echo "Can't seem to find supported firewall software. Check your path?" && exit 255 )
	
check_gpg:
	@echo "Looking for gpg..."
	@which gpg >/dev/null  || ( echo "Can't seem to find gpg in your path. Is it installed?"  && exit 255 )

check_gpgv:
	@echo "Looking for gpgv..."
	@which gpgv > /dev/null || ( echo "Can't seem to find gpgv in your path. Is it installed?" && exit 255 )

install_bin:
	$(INSTALL) $(INST_BIN) $(TARGET)

install_etc:
	[ -d $(TARGET)/$(INST_ETC) ] || mkdir $(TARGET)/$(INST_ETC)
	$(INSTALL) $(INST_ETC)/passwd   $(TARGET)/$(INST_ETC)
	$(INSTALL) $(INST_ETC)/group    $(TARGET)/$(INST_ETC)
	$(INSTALL) $(INST_ETC)/groupadm $(TARGET)/$(INST_ETC)

install_forms:
	[ -d $(TARGET)/$(INST_FORMS) ] || $(INSTALL) $(INST_FORMS) $(TARGET)

install_gw: $(TARGET) install_forms install_bin
	@echo "Installing NoCat to $(TARGET)..."
	$(INSTALL) $(INST_GW) $(TARGET)

wrapper: check_fw
	FW_BIN=`bin/detect-fw.sh | cut -d' ' -f1`; \
	ln -sf fw-wrap bin/`basename $$FW_BIN`; \
	gcc -o bin/fw-wrap -Wall -DALLOWED_UID=\"$(WRAP_USER)\" \
	    -DFW_BINARY=\"$$FW_BIN\" \
	    etc/fw-wrap.c
	chmod u+s bin/fw-wrap

base_gateway:
	[ -f $(TARGET)/nocat.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' gateway.conf \
		> $(TARGET)/nocat.conf
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo "                  Congratulations!"
	@echo "  NoCat gateway is installed.  To start it, check"
	@echo "  $(PREFIX)/nocat.conf, then run bin/gateway"
	@echo "  as root."
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo

chown_gateway:
	chown $(WRAP_USER) $(TARGET)
	chown $(WRAP_USER) $(TARGET)/pgp

suid-gateway: check_gpgv wrapper install_gw chown_gateway base_gateway

gateway: check_gpgv check_fw install_gw base_gateway

authserv: check_gpg install_gw install_etc
	$(INSTALL) $(INST_SERV) $(TARGET)
	[ -f $(TARGET)/nocat.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' authserv.conf \
		> $(TARGET)/nocat.conf
	[ -f $(TARGET)/httpd.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' etc/httpd.conf \
		> $(TARGET)/httpd.conf
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo
	@echo "  Congratulations! NoCat Authserv is installed."
	@echo
	@echo "  You will find a database schema in etc/nocat.schema."
	@echo
	@echo "  You will find suitable defaults to include in your Apache configuration"
	@echo "    in $(PREFIX)/httpd.conf".
	@echo
	@echo "  You may wish to run 'make pgpkey' now to generate your service's PGP keys."
	@echo
	@echo "  GOOD LUCK!"
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo

pgpkey: check_gpg
	[ -d $(TARGET)/pgp ] || mkdir $(TARGET)/pgp
	chmod 700 $(TARGET)/pgp
	gpg --homedir=$(TARGET)/pgp --gen-key
	$(INSTALL) $(TARGET)/pgp/pubring.gpg $(TARGET)/trustedkeys.gpg
	@echo
	@echo "Be sure to make your $(PREFIX)/pgp directory readable *only* by the user"
	@echo "    your httpd runs as."
	@echo
	@echo "The public key ring you'll need to distribute can be found in"
	@echo "	   $(PREFIX)/trustedkeys.gpg."
	@echo

