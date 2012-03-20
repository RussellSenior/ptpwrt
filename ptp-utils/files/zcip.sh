# ptp-utils/files/zcip.sh: OpenWrt support for proto zcip network interfaces
# Copyright 2012 Personal Telco Project

stop_interface_zcip() {
        service_stop /sbin/zcip
}

setup_interface_zcip() {
	local iface="$1"
	local config="$2"

	local mtu
	config_get mtu "$config" mtu 1492

        ifconfig "$iface" mtu "$mtu"

        service_start /sbin/zcip "$iface" /usr/share/zcip/zcip.script
}

