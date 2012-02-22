# ptp-node/Makefile: OpenWrt metapackage for PTP nodes
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=ptp-node
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ptp-node
  SECTION:=ptp
  CATEGORY:=PTP
  TITLE:=Node metapackage for Personal Telco devices
  URL:=https://personaltelco.net/wiki/OpenWrt
  MAINTAINER:=Keegan Quinn <keegan@personaltelco.net>
  DEPENDS:=+ptp-utils \
	+dnsmasq \
	+dropbear \
	+kmod-batman-adv \
	+iftop \
	+net-snmp \
	+nocatauth \
	+olsrd \
	+openvpn \
	+radvd \
	+rsync \
	+wget
endef

define Package/ptp-node/description
 Meta-configuration option which depends on all software which is
 used in common Personal Telco Project node installations.

 Depends on:
 - ptp-utils (TODO!)
 - dnsmasq
 - dropbear
 - kmod-batman-adv
 - curl
 - iftop
 - net-snmp
 - nocatauth
 - olsrd
 - openvpn
 - radvd
 - rsync
 - tcpdump-mini
 - wget
endef

define Package/ptp-node/install
	true
endef

$(eval $(call BuildPackage,ptp-node))

