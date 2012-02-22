# nocatauth-ptp/Makefile: OpenWrt package for the PTP version of NoCatAuth
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=nocatauth-ptp
PKG_VERSION:=0.90
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/nocatauth-ptp
  SECTION:=ptp
  CATEGORY:=PTP
  TITLE:=NoCatAuth captive portal - Personal Telco edition
  URL:=https://personaltelco.net/wiki/NoCatAuth
  MAINTAINER:=Keegan Quinn <keegan@personaltelco.net>
  DEPENDS:=+perl \
	+perlbase-essential \
	+perlbase-posix \
	+perlbase-autoloader \
	+perlbase-xsloader \
	+perlbase-fcntl \
	+perlbase-tie \
	+perlbase-getopt \
	+perlbase-findbin \
	+perlbase-cwd \
	+perlbase-config \
	+perlbase-file \
	+perlbase-sigtrap \
	+perlbase-io \
	+perlbase-symbol \
	+perlbase-selectsaver \
	+perlbase-socket \
	+perlbase-errno \
	+kmod-ipt-ipopt \
	+kmod-ipt-nat-extra \
	+iptables-mod-ipopt \
	+iptables-mod-nat-extra
endef

define Package/nocatauth-ptp/description
 NoCatAuth is the original "catch and release" captive portal
 implementation. It provides a simple splash screen web page for
 clients on your network. It is written in Perl.

 This is the Personal Telco version of NoCatAuth, with several
 patches and customizations. It may not be suitable for general use.
endef

define Package/nocatauth-ptp/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/nocatauth.config $(1)/etc/config/nocatauth

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nocatauth.init $(1)/etc/init.d/nocatauth

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/bin/gateway $(1)/usr/bin/nocatauth

	$(INSTALL_DIR) $(1)/usr/lib/perl5
	$(CP) -r ./files/lib/* $(1)/usr/lib/perl5/

	$(INSTALL_DIR) $(1)/usr/lib/nocatauth
	$(CP) -r ./files/libexec/* $(1)/usr/lib/nocatauth/

	$(INSTALL_DIR) $(1)/www
	$(CP) -r ./files/www/* $(1)/www/
endef

define Package/nocatauth-ptp/conffiles
/etc/config/nocatauth
endef

$(eval $(call BuildPackage,nocatauth-ptp))

