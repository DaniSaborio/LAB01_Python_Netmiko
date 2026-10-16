#!/usr/bin/env python3
"""
Configuración inicial de LAB01 (GNS3 local) por consola, para que
lab1_inventario.py pueda entrar por SSH.

Deja la topología igual al enunciado del Lab 1:

    host (tap0) 10.60.30.1 ── Switch1 ──┬── MikroTik ether1 10.60.30.202  ── ether2 172.16.20.1 ── PC2 .100
                                        └── R1 (Cisco) Fa0/0 10.60.30.203 ── Fa0/1  172.16.10.1 ── PC1 .11

Qué hace (todo es idempotente, se puede correr varias veces):
  - R1:       hostname cisco-lab, IPs, ruta por defecto, usuario lab-ssh, SSH v2.
  - MikroTik: identidad mt-lab, IPs, ruta por defecto, usuario lab-ssh, SSH y REST (https).
  - PC1/PC2:  IP y gateway.

Claves: LAB_PASS_MT_LAB y LAB_PASS_CISCO_LAB (las mismas que usa el lab, desde
el entorno o el .env). La clave de admin del MikroTik sale de LAB_ADMIN_MT_LAB;
si no existe se usa LAB_PASS_MT_LAB.

Uso (nodos encendidos en GNS3):
    python laboratorio_local/preparar_equipos.py
    python laboratorio_local/preparar_equipos.py --solo mikrotik
    python laboratorio_local/preparar_equipos.py --puerto-mikrotik 5004 --puerto-cisco 5016
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import socket
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
TOPOLOGIA = BASE_DIR / "LAB01.gns3"
load_dotenv(BASE_DIR / ".env")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")
IAC = 255


# ─────────────────────────────────────────────────────────────────────────────
# Consola telnet mínima (telnetlib ya no existe en Python 3.13+)
# ─────────────────────────────────────────────────────────────────────────────
class Consola:
    def __init__(self, puerto: int, host: str = "127.0.0.1"):
        self.sock = socket.create_connection((host, puerto), timeout=10)
        self.buffer = ""

    @staticmethod
    def _limpiar(datos: bytes) -> str:
        """Quita la negociación telnet (IAC ...) y los códigos ANSI."""
        salida = bytearray()
        i = 0
        while i < len(datos):
            if datos[i] == IAC and i + 1 < len(datos):
                comando = datos[i + 1]
                if comando == 250:  # subnegociación: saltar hasta IAC SE
                    fin = datos.find(bytes([IAC, 240]), i)
                    i = len(datos) if fin < 0 else fin + 2
                elif comando in (251, 252, 253, 254):
                    i += 3
                else:
                    i += 2
                continue
            salida.append(datos[i])
            i += 1
        return ANSI.sub("", salida.decode(errors="ignore"))

    def enviar(self, linea: str) -> None:
        self.sock.sendall(linea.encode() + b"\r")

    def esperar(self, patrones: list[str], timeout: float = 30) -> tuple[int, str]:
        """Lee hasta que algún patrón aparezca. Devuelve (índice, texto leído)."""
        regex = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patrones]
        limite = time.time() + timeout
        while time.time() < limite:
            for i, r in enumerate(regex):
                m = r.search(self.buffer)
                if m:
                    texto, self.buffer = self.buffer[: m.end()], self.buffer[m.end():]
                    return i, texto
            self.sock.settimeout(max(0.1, min(1.0, limite - time.time())))
            try:
                datos = self.sock.recv(65535)
            except socket.timeout:
                continue
            if not datos:
                raise ConnectionError("la consola cerró la conexión")
            self.buffer += self._limpiar(datos)
        raise TimeoutError(f"no apareció {patrones} en {timeout}s. Último texto: {self.buffer[-200:]!r}")

    def cerrar(self) -> None:
        self.sock.close()


def clave(variable: str, respaldo: str | None = None) -> str:
    valor = os.getenv(variable) or (os.getenv(respaldo) if respaldo else None)
    return valor or getpass.getpass(f"Clave para {variable}: ")


def puertos_desde_topologia() -> dict[str, int]:
    """Lee los puertos de consola de LAB01.gns3 según el tipo de nodo."""
    puertos: dict[str, int] = {}
    nodos = json.loads(TOPOLOGIA.read_text())["topology"]["nodes"]
    for nodo in nodos:
        tipo, nombre, puerto = nodo["node_type"], nodo["name"].upper(), nodo.get("console")
        if not puerto:
            continue
        if tipo == "dynamips":
            puertos["cisco"] = puerto
        elif tipo == "qemu":
            puertos["mikrotik"] = puerto
        elif tipo == "vpcs":
            puertos[nombre.lower()] = puerto
    return puertos


# ─────────────────────────────────────────────────────────────────────────────
# Cisco 3725 (R1)
# ─────────────────────────────────────────────────────────────────────────────
def configurar_cisco(puerto: int) -> None:
    password = clave("LAB_PASS_CISCO_LAB")
    con = Consola(puerto)
    print(f"[cisco] consola 127.0.0.1:{puerto} (si el router está arrancando, esto tarda)")

    # Llegar al modo privilegiado sin importar en qué estado esté el router
    patrones = [
        r"initial configuration dialog\?.*\[yes/no\]:",  # 0 router sin config
        r"terminate autoinstall\? \[yes\]:",              # 1
        r"Press RETURN to get started",                   # 2
        r"^Username:\s*$",                                # 3
        r"^Password:\s*$",                                # 4
        r"^\S+>\s*$",                                     # 5
        r"^\S+#\s*$",                                     # 6
    ]
    con.enviar("")
    for _ in range(20):
        i, _ = con.esperar(patrones, timeout=240)
        if i == 0:
            con.enviar("no")
        elif i == 1:
            con.enviar("yes")
        elif i == 2:
            con.enviar("")
        elif i == 3:
            con.enviar("lab-ssh")
        elif i == 4:
            con.enviar(password)
        elif i == 5:
            con.enviar("enable")
        else:
            break
    else:
        raise RuntimeError("no se pudo llegar al modo privilegiado de R1")

    prompt = [r"^\S+[#>]\s*$"]
    configuracion = [
        "terminal length 0",
        "configure terminal",
        "hostname cisco-lab",
        "no ip domain lookup",
        "ip domain name lab.local",
        f"username lab-ssh privilege 15 secret {password}",
        "interface FastEthernet0/0",
        " description LAN-10.60.30 (Switch1)",
        " ip address 10.60.30.203 255.255.255.0",
        " no shutdown",
        "interface FastEthernet0/1",
        " description LAN PC1",
        " ip address 172.16.10.1 255.255.255.0",
        " no shutdown",
        "exit",
        "ip route 0.0.0.0 0.0.0.0 10.60.30.1",
        "line vty 0 4",
        " login local",
        " transport input ssh",
        "exit",
    ]
    for linea in configuracion:
        con.enviar(linea)
        con.esperar(prompt, timeout=20)

    # Las llaves RSA solo se generan si no existen (si existen, IOS pregunta)
    con.enviar("crypto key generate rsa general-keys modulus 1024")
    i, _ = con.esperar([r"\[yes/no\]:", r"^\S+\(config\)#\s*$"], timeout=120)
    if i == 0:
        con.enviar("no")
        con.esperar(prompt, timeout=20)
    for linea in ("ip ssh version 2", "end", "write memory"):
        con.enviar(linea)
        con.esperar(prompt, timeout=60)

    con.enviar("show ip interface brief | include FastEthernet")
    _, salida = con.esperar(prompt, timeout=20)
    print(salida.strip())
    con.cerrar()
    print("[cisco] listo: cisco-lab 10.60.30.203, usuario lab-ssh, SSH v2")


# ─────────────────────────────────────────────────────────────────────────────
# MikroTik CHR 7.x
# ─────────────────────────────────────────────────────────────────────────────
def ros_texto(valor: str) -> str:
    """Escapa un valor para ponerlo entre comillas en RouterOS."""
    return valor.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def configurar_mikrotik(puerto: int) -> None:
    password = clave("LAB_PASS_MT_LAB")
    admin = clave("LAB_ADMIN_MT_LAB", respaldo="LAB_PASS_MT_LAB")
    con = Consola(puerto)
    print(f"[mikrotik] consola 127.0.0.1:{puerto}")

    patrones = [
        r"Login:\s*$",                                    # 0
        r"^Password:\s*$",                                # 1
        r"license\?.*\[Y/n\]:?\s*$",                      # 2
        r"repeat new password>\s*$",                      # 3
        r"new password>\s*$",                             # 4
        r"\] >\s*$",                                      # 5 prompt [admin@mt-lab] >
        r"Login failed",                                  # 6
    ]
    # Primero sin clave (CHR de fábrica), luego con la clave de admin.
    claves_admin = ["", admin]
    intento = 0
    con.enviar("")
    for _ in range(20):
        i, _ = con.esperar(patrones, timeout=180)
        if i == 0:
            # +ct: sin colores ni detección de terminal, salida fácil de leer
            con.enviar("admin+ct")
        elif i == 1:
            if intento >= len(claves_admin):
                raise RuntimeError("no se pudo entrar como admin (revise LAB_ADMIN_MT_LAB)")
            con.enviar(claves_admin[intento])
            intento += 1
        elif i == 2:
            con.enviar("n")
        elif i in (3, 4):
            con.enviar(admin)
        elif i == 5:
            break
    else:
        raise RuntimeError("no se pudo llegar al prompt del MikroTik")

    pw = ros_texto(password)
    comandos = [
        "/system identity set name=mt-lab",
        ':if ([:len [/ip address find address="10.60.30.202/24"]] = 0) do={'
        '/ip address add address=10.60.30.202/24 interface=ether1 comment="LAB-LOCAL"}',
        ':if ([:len [/ip address find address="172.16.20.1/24"]] = 0) do={'
        '/ip address add address=172.16.20.1/24 interface=ether2 comment="LAB-LOCAL LAN PC2"}',
        ':if ([:len [/ip route find dst-address="0.0.0.0/0" gateway="10.60.30.1"]] = 0) do={'
        '/ip route add dst-address=0.0.0.0/0 gateway=10.60.30.1 comment="LAB-LOCAL"}',
        "/ip service set ssh disabled=no port=22",
        # REST en RouterOS 7.8 solo va por HTTPS (www-ssl): certificado autofirmado
        ':if ([:len [/certificate find name="lab-rest"]] = 0) do={'
        '/certificate add name=lab-rest common-name=10.60.30.202 days-valid=3650; '
        '/certificate sign lab-rest}',
        "/ip service set www-ssl certificate=lab-rest disabled=no port=443",
        f':if ([:len [/user find name="lab-ssh"]] = 0) do={{'
        f'/user add name=lab-ssh group=full password="{pw}"}} '
        f'else={{/user set [find name="lab-ssh"] password="{pw}"}}',
        "/ip address print terse",
    ]
    for comando in comandos:
        con.enviar(comando)
        _, salida = con.esperar([r"\] >\s*$"], timeout=20)
        if re.search(r"failure|syntax error|bad command|expected", salida, re.IGNORECASE):
            raise RuntimeError(f"RouterOS rechazó: {comando}\n{salida}")
    print("\n".join(l for l in salida.splitlines() if "address=" in l))
    con.enviar("/quit")
    con.cerrar()
    print("[mikrotik] listo: mt-lab 10.60.30.202, usuario lab-ssh, SSH y REST (https)")


# ─────────────────────────────────────────────────────────────────────────────
# VPCS
# ─────────────────────────────────────────────────────────────────────────────
VPCS = {
    "pc1": ("172.16.10.11/24", "172.16.10.1"),   # detrás del Cisco
    "pc2": ("172.16.20.100/24", "172.16.20.1"),  # detrás del MikroTik
}


def configurar_vpcs(nombre: str, puerto: int) -> None:
    ip, gw = VPCS[nombre]
    con = Consola(puerto)
    con.enviar("")
    con.esperar([r"\S+>\s*$"], timeout=15)
    for linea in (f"ip {ip} {gw}", "save"):
        con.enviar(linea)
        con.esperar([r"\S+>\s*$"], timeout=15)
    con.cerrar()
    print(f"[{nombre}] {ip} gw {gw}")


def main() -> int:
    puertos = puertos_desde_topologia()
    p = argparse.ArgumentParser(description="Configuración inicial de LAB01 por consola")
    p.add_argument("--solo", choices=["cisco", "mikrotik", "vpcs"], help="configurar solo uno")
    p.add_argument("--puerto-cisco", type=int, default=puertos.get("cisco"))
    p.add_argument("--puerto-mikrotik", type=int, default=puertos.get("mikrotik"))
    args = p.parse_args()

    tareas = []
    if args.solo in (None, "mikrotik"):
        tareas.append(("mikrotik", lambda: configurar_mikrotik(args.puerto_mikrotik)))
    if args.solo in (None, "cisco"):
        tareas.append(("cisco", lambda: configurar_cisco(args.puerto_cisco)))
    if args.solo in (None, "vpcs"):
        for nombre in VPCS:
            if nombre in puertos:
                tareas.append((nombre, lambda n=nombre: configurar_vpcs(n, puertos[n])))

    errores = 0
    for nombre, tarea in tareas:
        try:
            tarea()
        except (OSError, TimeoutError, RuntimeError, ConnectionError) as e:
            errores += 1
            print(f"[{nombre}] ERROR: {e}  (¿el nodo está encendido en GNS3?)", file=sys.stderr)
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
