# ptp-utils/Makefile: OpenWrt package for miscellaneous utilities
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=ptp-utils
PKG_VERSION:=0.2
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

define Package/ptp-utils/config
	select BUSYBOX_CONFIG_ZCIP
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

Also includes support for the 'zcip' network configuration mode, which uses
the zcip tool to configure a ZeroConf IPv4 link-local address.
endef

define Build/Compile
endef

define Build/Configure
endef

define Package/ptp-utils/install
	$(INSTALL_DIR) $(1)/lib/network
	$(INSTALL_BIN) ./files/zcip.sh $(1)/lib/network/zcip.sh

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/assoc-count $(1)/usr/bin/assoc-count
	$(INSTALL_BIN) ./files/client-status $(1)/usr/bin/client-status
	$(INSTALL_BIN) ./files/watch-traffic $(1)/usr/bin/watch-traffic
	$(INSTALL_BIN) ./files/wimax-down $(1)/usr/bin/wimax-down
	$(INSTALL_BIN) ./files/wimax-scrape $(1)/usr/bin/wimax-scrape
	$(INSTALL_BIN) ./files/wimax-sig $(1)/usr/bin/wimax-sig
	$(INSTALL_BIN) ./files/wimax-up $(1)/usr/bin/wimax-up

	$(INSTALL_DIR) $(1)/usr/share/zcip
	$(INSTALL_BIN) ./files/zcip.script $(1)/usr/share/zcip/zcip.script
endef

$(eval $(call BuildPackage,ptp-utils))

