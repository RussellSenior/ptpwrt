Personal Telco Project packages for OpenWrt
===========================================

For more information about OpenWrt, visit https://openwrt.org/

For more information about the Personal Telco Project, visit https://personaltelco.net/wiki/

Concept
-------

The goal of this project is to simplify and standardize Personal Telco OpenWrt
node device image creation. One should be able to build a correct image by
simply selecting the appropriate hardware options and the ptp-node
metapackage, then dropping the desired configuration files into place.

In the future, this should help mitigate the problems and mysteries associated
with retaining and copying build .config files, and make it easier to work
with new device types which are supported by OpenWrt.

Usage
-----

Add to your feeds.conf:

    src-git ptpwrt git://github.com/keeganquinn/ptpwrt.git

Then retrieve and install the packages:

    scripts/feeds update ptpwrt
    scripts/feeds install -a -p ptpwrt

The packages will be available for selection in the OpenWrt build
configuration system, under a new PTP menu.

