# ptp-node/Makefile: OpenWrt metapackage for PTP nodes
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=ptp-node
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ptp-node
  TITLE:=Personal Telco Project node metapackage
  URL:=https://personaltelco.net/wiki/OpenWrt
  DEPENDS:=+ptp-utils \
  	+dnsmasq \
  	+dropbear \
	+batman-adv \
	+curl \
	+iftop \
	+net-snmp
endef

define Package/ptp-node/description
 Meta-configuration option which depends on all software which is
 used in common Personal Telco Project node installations.

 Depends on:
 - ptp-utils
 - dnsmasq
 - dropbear
 - batman-adv
 - curl
 - iftop
 - net-snmp
endef

$(eval $(call Package,ptp-node))

