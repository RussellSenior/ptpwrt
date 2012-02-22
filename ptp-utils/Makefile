# ptp-utils/Makefile: OpenWrt package for miscellaneous utilities
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=ptp-utils
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ptp-utils
  SECTION:=ptp
  CATEGORY:=PTP
  TITLE:=Miscellaneous utilities for Personal Telco devices
  URL:=https://personaltelco.net/wiki/OpenWrt
  MAINTAINER:=Keegan Quinn <keegan@personaltelco.net>
  DEPENDS:=+curl +tcpdump-mini
endef

define Package/ptp-utils/description
Assorted utility scripts which are frequently used in common
Personal Telco Project node installations.

Includes the following scripts:
 - assoc-count
 - client-status
 - watch-traffic
 - wimax-scrape
 - wimax-sig
 - wimax-up
 - wimax-down
endef

define Build/Compile
endef

define Build/Configure
endef

define Package/ptp-utils/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/assoc-count $(1)/usr/bin/assoc-count
	$(INSTALL_BIN) ./files/client-status $(1)/usr/bin/client-status
	$(INSTALL_BIN) ./files/watch-traffic $(1)/usr/bin/watch-traffic
	$(INSTALL_BIN) ./files/wimax-down $(1)/usr/bin/wimax-down
	$(INSTALL_BIN) ./files/wimax-scrape $(1)/usr/bin/wimax-scrape
	$(INSTALL_BIN) ./files/wimax-sig $(1)/usr/bin/wimax-sig
	$(INSTALL_BIN) ./files/wimax-up $(1)/usr/bin/wimax-up
endef

$(eval $(call BuildPackage,ptp-utils))

