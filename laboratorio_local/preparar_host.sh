#!/usr/bin/env bash
# Conecta este Linux a la LAN 10.60.30.0/24 de LAB01 (sin VPN).
# Cloud1 en GNS3 usa la interfaz tap0, enlazada a Switch1. Al darle la IP .1
# el host queda en la LAN y además es el gateway por defecto de los routers.
#
# Uso (con LAB01 abierto en GNS3 y los nodos encendidos):
#   ./laboratorio_local/preparar_host.sh            # tap0, 10.60.30.1/24
#   ./laboratorio_local/preparar_host.sh tap0 10.60.30.1/24
#
# tap0 la crea GNS3 (ubridge) al abrir el proyecto y desaparece al cerrarlo,
# así que hay que correr esto cada vez que se abre LAB01.
set -euo pipefail

IFACE="${1:-tap0}"
IP="${2:-10.60.30.1/24}"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "No existe la interfaz $IFACE. Abra LAB01 en GNS3 primero (Cloud1 la crea)." >&2
    exit 1
fi

sudo ip addr replace "$IP" dev "$IFACE"
sudo ip link set "$IFACE" up

echo "Listo: $IFACE con $IP"
ip -br addr show "$IFACE"
