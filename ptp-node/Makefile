# ptp-node/Makefile: OpenWrt metapackage for PTP nodes
# Copyright 2012 Personal Telco Project

include $(TOPDIR)/rules.mk

PKG_NAME:=ptp-node
PKG_VERSION:=0.2
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
	+wireless-tools \
	+ip6tables \
	+traceroute6 \
	+radvd \
	+kmod-batman-adv \
	+kmod-lib80211 \
	+nocatauth \
	+curl \
	+hostapd-mini \
	+iftop \
	+ip \
	+iw \
	+iwinfo \
	+olsrd \
	+openvpn \
	+procps \
	+radvd \
	+rsync \
	+snmpd \
	+tcpdump-mini \
	+wget \
	+wpad-mini
endef

define Package/ptp-node/config
	select BUSYBOX_CONFIG_NTPD
	select BUSYBOX_CONFIG_ZCIP
endef

define Package/ptp-node/description
Meta-configuration option which depends on all software which is
used in common Personal Telco Project node installations.

Depends on:
 - ptp-utils
 - dnsmasq
 - dropbear
 - wireless-tools
 - ip6tables
 - traceroute6
 - radvd
 - kmod-batman-adv
 - kmod-lib80211
 - nocatauth
 - curl
 - hostapd-mini
 - iftop
 - ip
 - iw
 - iwinfo
 - olsrd
 - openvpn
 - procps
 - radvd
 - rsync
 - snmpd
 - tcpdump-mini
 - wget
 - wpad-mini

Selecting this package will also select certain configuration options which
are needed to use the standard PTP settings.
endef

define Build/Compile
endef

define Build/Configure
endef

define Package/ptp-node/install
endef

$(eval $(call BuildPackage,ptp-node))

