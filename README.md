# dnspark — Blocker DNS para Orange Pi (Allwinner H3 512MB RAM from Ali Express) con Buildroot

Se utiliza un Daemon que escucha por UDP en el puerto 53, bloquea dominios de una lista y reenvía el resto a un upstream.
Cross-compilation con Buildroot para correr embebidamente en la tarjeta.
## Estructura

- `src/main.c` — daemon completo (single file)
- `blocklists/` — blocklists de ejemplo (formato hosts o dominio/línea)
- `buildroot/` — receta Buildroot (paquete local + overlay con init script)
- `Makefile` — build nativo para probar en la laptop

### Integración del paquete

`buildroot/package/dnspark/Config.in` + `.mk` apuntan a este repo
(local site method). En `menuconfig` → Target packages → Network
applications → dnspark.

### Cargar la imagen a la placa

```sh
sudo dd if=output/images/sdcard.img of=/dev/sdX bs=4M status=progress
```

Arranca, y dnspark corre como servicio de Busybox init.

## Uso en la tarjeta

- Blocklist en `/etc/dnspark/blocklist` (overlay la instala)
- `SIGHUP` recarga la blocklist sin reiniciar
- Apunta los clientes (DHCP DNS = IP de la OPi) o cambia resolv.conf
- Test: `dig @<ip_opi> doubleclick.net` → NXDOMAIN
