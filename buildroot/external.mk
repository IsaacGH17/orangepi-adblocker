# external.mk — requerido por Buildroot; los paquetes del external tree
# incorporan sus recetas automáticamente desde package/*/*.mk
include $(sort $(wildcard $(BR2_EXTERNAL_DNSPARK_EXT_PATH)/package/*/*.mk))
