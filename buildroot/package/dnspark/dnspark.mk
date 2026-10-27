################################################################################
#
# dnspark
#
################################################################################

DNSPARK_VERSION = 1.0
# pkgdir = este directorio (buildroot/package/dnspark) — solo código fuente
# sin submodule ni output/ (la causa del rsync infinito de la versión anterior)
# Path absoluta al dir del paquete en el external tree — $(pkgdir) NO es
# fiable en parse time (se expandió a docs/manual: rsync copió el manual)
DNSPARK_SITE = $(BR2_EXTERNAL_DNSPARK_EXT_PATH)/package/dnspark
DNSPARK_SITE_METHOD = local
DNSPARK_LICENSE = MIT
DNSPARK_LICENSE_FILES = LICENSE

define DNSPARK_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(TARGET_CC) $(TARGET_CFLAGS) \
		-std=c99 -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-o $(@D)/dnspark $(@D)/main.c
endef

define DNSPARK_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/dnspark \
		$(TARGET_DIR)/usr/bin/dnspark
	$(INSTALL) -D -m 0644 $(@D)/blocklist \
		$(TARGET_DIR)/etc/dnspark/blocklist
	$(INSTALL) -D -m 0755 $(BR2_EXTERNAL_DNSPARK_EXT_PATH)/overlay/etc/init.d/S60dnspark \
		$(TARGET_DIR)/etc/init.d/S60dnspark
endef

$(eval $(generic-package))
