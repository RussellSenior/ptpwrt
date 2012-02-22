Personal Telco Project packages for OpenWrt
===========================================

For more information about OpenWrt, visit https://openwrt.org/

For more information about the Personal Telco Project, visit https://personaltelco.net/wiki/

Usage
-----

Add to your feeds.conf:

    src-git ptpwrt git://github.com/keeganquinn/ptpwrt.git

Then retrieve and install the packages:

    scripts/feeds update ptpwrt
    scripts/feeds install -a -p ptpwrt

The packages will be available for selection in the OpenWrt build configuration
system, under a new PTP menu.

