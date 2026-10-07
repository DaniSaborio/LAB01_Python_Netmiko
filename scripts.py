#!/usr/bin/env python3
"""
Laboratorio 1 — Inventario, estado y configuración segura con Python + SSH (Netmiko)
ITIEL-13 Redes Programables · UTN · III-2026

Uso:
    python lab1_inventario.py                  # R1–R6: estado + cambio idempotente
    python lab1_inventario.py --solo-estado    # solo lectura (no toca configuración)
    python lab1_inventario.py --limpiar        # elimina SOLO mis objetos (lo-ssh-N)
    python lab1_inventario.py --rest           # extra: compara SSH vs API REST
    python lab1_inventario.py -i otro.yaml -n 7

Credenciales (R2): variable de entorno LAB_PASS_<NOMBRE> (mt-lab -> LAB_PASS_MT_LAB);
si no existe, se piden con getpass. Nunca se guardan en código, YAML ni reporte.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Constantes y rutas
# ─────────────────────────────────────────────────────────────────────────────
console = Console()

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTE_JSON = BASE_DIR / "reporte_estado.json"

CAMPOS_OBLIGATORIOS = ("nombre", "host", "device_type", "usuario", "rol")
ROLES_VALIDOS = ("lectura", "escritura")
CAMPOS_PROHIBIDOS = ("password", "clave", "contrasena", "contraseña", "secret")

# R4: comandos por device_type. Agregar un fabricante = agregar una entrada aquí
# (y sus parsers en PARSERS). Nada de if por equipo.
COMANDOS: dict[str, dict[str, str]] = {
    "mikrotik_routeros": {
        "identidad": "/system identity print",
        "uptime": "/system resource print",
        "interfaces": "/ip address print terse",
        "ruta_default": "/ip route print terse where dst-address=0.0.0.0/0",
    },
    "cisco_ios": {
        "identidad": "show running-config | include hostname",
        "uptime": "show version | include uptime",
        "interfaces": "show ip interface brief",
        "ruta_default": "show ip route 0.0.0.0",
    },
}

# Palabras que RouterOS devuelve cuando un comando falla
RE_ERROR_ROUTEROS = re.compile(
    r"failure|bad command|syntax error|invalid value|expected end|no such item|"
    r"input does not match",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Utilidades de parseo (texto -> estructuras)
# ─────────────────────────────────────────────────────────────────────────────
RE_KV = re.compile(r'([\w.-]+)=("[^"]*"|\S+)')
RE_ENCABEZADO_TERSE = re.compile(r"^\s*(\d+)\s+(?:([A-Za-z*+]+)\s+)?(?=[\w.-]+=)")


def texto_a_dict(texto: str) -> dict[str, str]:
    """Convierte salidas 'clave: valor' (ej. /system resource print) en dict."""
    datos: dict[str, str] = {}
    for linea in texto.splitlines():
        if ":" not in linea:
            continue
        clave, valor = linea.split(":", 1)
        clave = clave.strip()
        if clave:
            datos[clave] = valor.strip()
    return datos


def terse_a_registros(texto: str) -> list[dict[str, str]]:
    """
    Convierte la salida de 'print terse' de RouterOS (una línea por registro)
    en una lista de dicts. Agrega '_id' y '_flags' (ej. 'A', 'D', 'X').
    """
    registros = []
    for linea in texto.splitlines():
        pares = RE_KV.findall(linea)
        if not pares:
            continue
        registro = {clave: valor.strip('"') for clave, valor in pares}
        encabezado = RE_ENCABEZADO_TERSE.match(linea)
        if encabezado:
            registro["_id"] = encabezado.group(1)
            registro["_flags"] = encabezado.group(2) or ""
        registros.append(registro)
    return registros


# ── Parsers MikroTik RouterOS ───────────────────────────────────────────────
def mt_parse_identidad(texto: str) -> dict:
    return {"hostname": texto_a_dict(texto).get("name", "")}


def mt_parse_uptime(texto: str) -> dict:
    d = texto_a_dict(texto)
    return {
        "uptime": d.get("uptime", ""),
        "version": d.get("version", ""),
        "board": d.get("board-name", ""),
        "cpu_load": d.get("cpu-load", ""),
    }


def mt_parse_interfaces(texto: str) -> list[dict]:
    return [
        {
            "interfaz": r.get("interface"),
            "ip": r.get("address"),
            "red": r.get("network"),
            "deshabilitada": "X" in r.get("_flags", ""),
            "dinamica": "D" in r.get("_flags", ""),
        }
        for r in terse_a_registros(texto)
        if "address" in r
    ]


def mt_parse_ruta_default(texto: str) -> dict:
    rutas = [r for r in terse_a_registros(texto) if r.get("dst-address") == "0.0.0.0/0"]
    if not rutas:
        return {}
    # Preferir la ruta activa (flag A)
    rutas.sort(key=lambda r: "A" not in r.get("_flags", ""))
    r = rutas[0]
    return {
        "destino": "0.0.0.0/0",
        "gateway": r.get("gateway"),
        "distancia": r.get("distance"),
        "activa": "A" in r.get("_flags", ""),
    }


# ── Parsers Cisco IOS (extra multivendor) ───────────────────────────────────
def ios_parse_identidad(texto: str) -> dict:
    m = re.search(r"^hostname\s+(\S+)", texto, re.MULTILINE)
    return {"hostname": m.group(1) if m else ""}


def ios_parse_uptime(texto: str) -> dict:
    m = re.search(r"uptime is\s+(.+)$", texto, re.MULTILINE)
    return {"uptime": m.group(1).strip() if m else ""}


def ios_parse_interfaces(texto: str) -> list[dict]:
    """show ip interface brief -> solo interfaces con IP asignada."""
    interfaces = []
    for linea in texto.splitlines():
        partes = linea.split()
        if len(partes) < 6 or partes[0] == "Interface":
            continue
        nombre, ip = partes[0], partes[1]
        if ip == "unassigned":
            continue
        interfaces.append(
            {
                "interfaz": nombre,
                "ip": ip,
                "estado": " ".join(partes[4:-1]),  # "up" / "administratively down"
                "protocolo": partes[-1],
            }
        )
    return interfaces


def ios_parse_ruta_default(texto: str) -> dict:
    if "not in table" in texto or not texto.strip():
        return {}
    gw = re.search(r"\*\s+(\d+\.\d+\.\d+\.\d+)", texto)
    directa = re.search(r"directly connected, via (\S+)", texto)
    return {
        "destino": "0.0.0.0/0",
        "gateway": gw.group(1) if gw else (directa.group(1) if directa else None),
    }


PARSERS: dict[str, dict[str, Callable[[str], Any]]] = {
    "mikrotik_routeros": {
        "identidad": mt_parse_identidad,
        "uptime": mt_parse_uptime,
        "interfaces": mt_parse_interfaces,
        "ruta_default": mt_parse_ruta_default,
    },
    "cisco_ios": {
        "identidad": ios_parse_identidad,
        "uptime": ios_parse_uptime,
        "interfaces": ios_parse_interfaces,
        "ruta_default": ios_parse_ruta_default,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# R1 — Inventario
# ─────────────────────────────────────────────────────────────────────────────
def cargar_inventario(ruta: Path) -> dict:
    """Lee y valida inventario.yaml. Falla si falta un campo o si hay claves."""
    if not ruta.exists():
        raise FileNotFoundError(f"No existe el inventario: {ruta}")

    with ruta.open(encoding="utf-8") as f:
        inventario = yaml.safe_load(f) or {}

    equipos = inventario.get("equipos") or []
    if not equipos:
        raise ValueError("El inventario no tiene equipos (clave 'equipos').")

    for i, equipo in enumerate(equipos, start=1):
        faltantes = [c for c in CAMPOS_OBLIGATORIOS if not equipo.get(c)]
        if faltantes:
            raise ValueError(f"Equipo #{i}: faltan campos {faltantes}")
        if equipo["rol"] not in ROLES_VALIDOS:
            raise ValueError(f"{equipo['nombre']}: rol debe ser {ROLES_VALIDOS}")
        prohibidos = [c for c in equipo if c.lower() in CAMPOS_PROHIBIDOS]
        if prohibidos:
            raise ValueError(
                f"{equipo['nombre']}: el YAML no puede contener credenciales {prohibidos} (R2)"
            )
    return inventario


# ─────────────────────────────────────────────────────────────────────────────
# R2 — Credenciales
# ─────────────────────────────────────────────────────────────────────────────
def nombre_variable_entorno(nombre_equipo: str) -> str:
    """mt-lab -> LAB_PASS_MT_LAB"""
    return "LAB_PASS_" + re.sub(r"[^A-Z0-9]", "_", nombre_equipo.upper())


def obtener_password(nombre_equipo: str) -> tuple[str, str]:
    """Devuelve (clave, origen). Origen: 'env' o 'getpass'."""
    variable = nombre_variable_entorno(nombre_equipo)
    clave = os.environ.get(variable)
    if clave:
        return clave, "env"
    console.print(f"  [yellow]⚠[/] [dim]{variable} no está definida[/]")
    return getpass.getpass(f"  🔑 Clave para {nombre_equipo}: "), "getpass"


# ─────────────────────────────────────────────────────────────────────────────
# R3 — Conexión
# ─────────────────────────────────────────────────────────────────────────────
def parametros_netmiko(equipo: dict, password: str) -> dict:
    """Arma el diccionario para ConnectHandler, con session_log por equipo."""
    LOGS_DIR.mkdir(exist_ok=True)
    return {
        "device_type": equipo["device_type"],
        "host": equipo["host"],
        "username": equipo["usuario"],
        "password": password,
        "port": equipo.get("puerto", 22),
        "session_log": str(LOGS_DIR / f"{equipo['nombre']}.log"),
        "conn_timeout": equipo.get("timeout", 15),
        "auth_timeout": equipo.get("timeout", 15),
    }


# ─────────────────────────────────────────────────────────────────────────────
# R4 — Estado estructurado
# ─────────────────────────────────────────────────────────────────────────────
def recolectar_estado(conn, device_type: str) -> dict:
    """Ejecuta los comandos del device_type y devuelve todo como dict."""
    comandos = COMANDOS[device_type]
    parsers = PARSERS[device_type]
    crudo = {clave: conn.send_command(cmd, read_timeout=30) for clave, cmd in comandos.items()}

    return {
        "hostname": parsers["identidad"](crudo["identidad"]).get("hostname", ""),
        "sistema": parsers["uptime"](crudo["uptime"]),
        "interfaces": parsers["interfaces"](crudo["interfaces"]),
        "ruta_default": parsers["ruta_default"](crudo["ruta_default"]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# R6 — Cambio idempotente en MikroTik
# ─────────────────────────────────────────────────────────────────────────────
def mt_consultar(conn, comando: str) -> list[dict]:
    """Ejecuta un 'print terse' y devuelve los registros."""
    return terse_a_registros(conn.send_command(comando, read_timeout=20))


def mt_ejecutar(conn, comando: str) -> str:
    """Ejecuta un comando de escritura y lanza error si RouterOS lo rechaza."""
    salida = conn.send_command(comando, read_timeout=20)
    if RE_ERROR_ROUTEROS.search(salida):
        raise RuntimeError(f"RouterOS rechazó «{comando}»: {salida.strip()}")
    return salida


def nombres_objetos(numero: int) -> tuple[str, str]:
    """Nombres de MIS objetos: (interfaz, ip/32)."""
    return f"lo-ssh-{numero}", f"10.253.0.{numero}/32"


def verificar_loopback(conn, numero: int) -> dict:
    """Lectura de verificación: ¿existe el bridge y tiene exactamente mi IP?"""
    interfaz, ip = nombres_objetos(numero)
    bridge = mt_consultar(conn, f'/interface bridge print terse where name="{interfaz}"')
    ips = mt_consultar(conn, f'/ip address print terse where interface="{interfaz}"')
    return {
        "bridge_existe": bool(bridge),
        "comentario": bridge[0].get("comment") if bridge else None,
        "ips": [r.get("address") for r in ips],
        "ok": bool(bridge) and [r.get("address") for r in ips] == [ip],
    }


def asegurar_loopback(conn, numero: int, autor: str) -> dict:
    """
    Consultar antes de crear. Asegura lo-ssh-N (bridge sin puertos) con
    10.253.0.N/32 y comentario. Una 2.ª ejecución no cambia nada.
    """
    interfaz, ip = nombres_objetos(numero)
    comentario = f"Lab1 {autor} N={numero}"
    pasos: list[tuple[str, str, str]] = []

    # 1) Bridge
    bridge = mt_consultar(conn, f'/interface bridge print terse where name="{interfaz}"')
    if not bridge:
        mt_ejecutar(
            conn,
            f'/interface bridge add name="{interfaz}" protocol-mode=none '
            f'comment="{comentario}"',
        )
        pasos.append(("Bridge", interfaz, "creado"))
    elif bridge[0].get("comment") != comentario:
        mt_ejecutar(
            conn,
            f'/interface bridge set [find where name="{interfaz}"] comment="{comentario}"',
        )
        pasos.append(("Bridge", interfaz, "comentario actualizado"))
    else:
        pasos.append(("Bridge", interfaz, "sin cambios"))

    # 2) Dirección IP (solo sobre MI interfaz)
    ips = mt_consultar(conn, f'/ip address print terse where interface="{interfaz}"')
    for sobrante in (r for r in ips if r.get("address") != ip):
        mt_ejecutar(
            conn,
            f'/ip address remove [find where interface="{interfaz}" '
            f'and address="{sobrante.get("address")}"]',
        )
        pasos.append(("IP sobrante", sobrante.get("address", "?"), "eliminada"))

    if any(r.get("address") == ip for r in ips):
        pasos.append(("Dirección IP", ip, "sin cambios"))
    else:
        mt_ejecutar(
            conn,
            f'/ip address add address={ip} interface="{interfaz}" comment="{comentario}"',
        )
        pasos.append(("Dirección IP", ip, "creada"))

    # 3) Verificación con lectura
    verificacion = verificar_loopback(conn, numero)
    return {
        "accion": "asegurar",
        "interfaz": interfaz,
        "ip": ip,
        "pasos": pasos,
        "hubo_cambios": any(p[2] != "sin cambios" for p in pasos),
        "verificacion": verificacion,
    }


def limpiar_loopback(conn, numero: int) -> dict:
    """--limpiar: elimina solo lo-ssh-N y sus IPs. Nada ajeno."""
    interfaz, _ = nombres_objetos(numero)
    pasos: list[tuple[str, str, str]] = []

    ips = mt_consultar(conn, f'/ip address print terse where interface="{interfaz}"')
    if ips:
        mt_ejecutar(conn, f'/ip address remove [find where interface="{interfaz}"]')
        for r in ips:
            pasos.append(("Dirección IP", r.get("address", "?"), "eliminada"))
    else:
        pasos.append(("Dirección IP", "—", "no existía"))

    bridge = mt_consultar(conn, f'/interface bridge print terse where name="{interfaz}"')
    if bridge:
        mt_ejecutar(conn, f'/interface bridge remove [find where name="{interfaz}"]')
        pasos.append(("Bridge", interfaz, "eliminado"))
    else:
        pasos.append(("Bridge", interfaz, "no existía"))

    verificacion = verificar_loopback(conn, numero)
    verificacion["ok"] = not verificacion["bridge_existe"] and not verificacion["ips"]
    return {
        "accion": "limpiar",
        "interfaz": interfaz,
        "pasos": pasos,
        "hubo_cambios": any(p[2] in ("eliminada", "eliminado") for p in pasos),
        "verificacion": verificacion,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Extra — API REST del MikroTik y comparación con SSH
# ─────────────────────────────────────────────────────────────────────────────
def estado_rest_mikrotik(equipo: dict, password: str) -> dict:
    """Obtiene los mismos 4 datos por https://<host>/rest con requests."""
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base = equipo.get("rest_url", f"https://{equipo['host']}/rest")
    sesion = requests.Session()
    sesion.auth = (equipo["usuario"], password)
    sesion.verify = False  # certificado autofirmado del laboratorio

    def get(ruta: str, **params):
        r = sesion.get(f"{base}{ruta}", params=params or None, timeout=10)
        r.raise_for_status()
        return r.json()

    recursos = get("/system/resource")
    rutas = get("/ip/route", **{"dst-address": "0.0.0.0/0"})
    rutas.sort(key=lambda r: r.get("active") != "true")
    return {
        "hostname": get("/system/identity").get("name", ""),
        "sistema": {"uptime": recursos.get("uptime", ""), "version": recursos.get("version", "")},
        "interfaces": [
            {"interfaz": a.get("interface"), "ip": a.get("address")}
            for a in get("/ip/address")
        ],
        "ruta_default": (
            {"destino": "0.0.0.0/0", "gateway": rutas[0].get("gateway")} if rutas else {}
        ),
    }


def comparar_ssh_rest(ssh: dict, rest: dict) -> list[dict]:
    """Compara campo por campo; el uptime puede variar unos segundos."""
    ips_ssh = sorted((i["interfaz"], i["ip"]) for i in ssh.get("interfaces", []))
    ips_rest = sorted((i["interfaz"], i["ip"]) for i in rest.get("interfaces", []))
    filas = [
        ("Hostname", ssh.get("hostname"), rest.get("hostname")),
        ("Versión", ssh["sistema"].get("version"), rest["sistema"].get("version")),
        ("Interfaces con IP", len(ips_ssh), len(ips_rest)),
        ("Gateway", ssh["ruta_default"].get("gateway"), rest["ruta_default"].get("gateway")),
    ]
    comparacion = [
        {"campo": c, "ssh": a, "rest": b, "coincide": a == b} for c, a, b in filas
    ]
    comparacion.insert(
        3, {"campo": "Lista de IPs", "ssh": len(ips_ssh), "rest": len(ips_rest),
            "coincide": ips_ssh == ips_rest},
    )
    comparacion.append(
        {"campo": "Uptime", "ssh": ssh["sistema"].get("uptime"),
         "rest": rest["sistema"].get("uptime"), "coincide": None}
    )
    return comparacion


# ─────────────────────────────────────────────────────────────────────────────
# Orquestación por equipo (R3: un fallo no detiene a los demás)
# ─────────────────────────────────────────────────────────────────────────────
def nuevo_resultado(equipo: dict) -> dict:
    return {
        "nombre": equipo["nombre"],
        "host": equipo["host"],
        "device_type": equipo["device_type"],
        "rol": equipo["rol"],
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "estado": "ok",
        "datos": {},
        "cambios": None,
        "rest": None,
    }


def procesar_equipo(equipo: dict, opciones: argparse.Namespace, estudiante: dict) -> dict:
    """Conecta, recolecta estado y (si aplica) aplica/limpia el cambio."""
    resultado = nuevo_resultado(equipo)
    device_type = equipo["device_type"]

    if device_type not in COMANDOS:
        resultado["estado"] = f"error: device_type '{device_type}' sin comandos definidos"
        return resultado

    password, origen = obtener_password(equipo["nombre"])
    console.print(f"  [dim]credencial desde:[/] [cyan]{origen}[/]")
    puede_escribir = equipo["rol"] == "escritura" and device_type == "mikrotik_routeros"

    try:
        with console.status(f"[bold cyan]Conectando a {equipo['host']} por SSH…", spinner="dots"):
            with ConnectHandler(**parametros_netmiko(equipo, password)) as conn:
                resultado["datos"] = recolectar_estado(conn, device_type)

                if puede_escribir and opciones.limpiar:
                    resultado["cambios"] = limpiar_loopback(conn, estudiante["numero"])
                elif puede_escribir and not opciones.solo_estado:
                    resultado["cambios"] = asegurar_loopback(
                        conn, estudiante["numero"], estudiante["nombre"]
                    )
    except NetmikoTimeoutException as e:
        resultado["estado"] = f"error: timeout de conexión ({str(e).splitlines()[0]})"
    except NetmikoAuthenticationException:
        resultado["estado"] = "error: autenticación fallida (usuario o clave)"
    except Exception as e:  # noqa: BLE001 — R3 pide capturar el resto por equipo
        resultado["estado"] = f"error: {type(e).__name__}: {e}"

    if opciones.rest and device_type == "mikrotik_routeros" and resultado["estado"] == "ok":
        try:
            with console.status("[bold magenta]Consultando API REST…", spinner="dots"):
                rest = estado_rest_mikrotik(equipo, password)
            resultado["rest"] = {
                "datos": rest,
                "comparacion": comparar_ssh_rest(resultado["datos"], rest),
            }
        except Exception as e:  # noqa: BLE001
            resultado["rest"] = {"error": f"{type(e).__name__}: {e}"}

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# R5 — Reporte JSON
# ─────────────────────────────────────────────────────────────────────────────
def guardar_reporte(resultados: list[dict], estudiante: dict, ruta: Path) -> None:
    documento = {
        "laboratorio": "ITIEL-13 Lab 1 — Inventario, estado y configuración segura",
        "estudiante": {"nombre": estudiante["nombre"], "numero_lista": estudiante["numero"]},
        "generado": datetime.now().isoformat(timespec="seconds"),
        "resumen": {
            "total": len(resultados),
            "ok": sum(r["estado"] == "ok" for r in resultados),
            "error": sum(r["estado"] != "ok" for r in resultados),
        },
        "equipos": resultados,
    }
    ruta.write_text(json.dumps(documento, indent=2, ensure_ascii=False), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Salida en consola (rich)
# ─────────────────────────────────────────────────────────────────────────────
COLOR_PASO = {
    "creado": "green", "creada": "green", "comentario actualizado": "yellow",
    "eliminado": "red", "eliminada": "red", "sin cambios": "dim", "no existía": "dim",
}


def mostrar_banner(opciones: argparse.Namespace, estudiante: dict, total: int) -> None:
    modo = (
        "[red]LIMPIEZA[/]" if opciones.limpiar
        else "[cyan]SOLO ESTADO[/]" if opciones.solo_estado
        else "[green]ESTADO + CONFIGURACIÓN[/]"
    )
    titulo = Text("LAB 1 · INVENTARIO NETMIKO", style="bold white")
    cuerpo = Text.from_markup(
        f"[bold]ITIEL-13 Redes Programables[/] · UTN · III-2026\n"
        f"Estudiante: [bold]{estudiante['nombre']}[/]  ·  N = [bold yellow]{estudiante['numero']}[/]\n"
        f"Equipos en inventario: [bold]{total}[/]  ·  Modo: {modo}"
        + ("  ·  [magenta]+REST[/]" if opciones.rest else "")
    )
    console.print(Panel(Group(titulo, cuerpo), box=box.DOUBLE, border_style="cyan", padding=(1, 2)))


def mostrar_encabezado_equipo(equipo: dict, i: int, total: int) -> None:
    rol = "[green]escritura[/]" if equipo["rol"] == "escritura" else "[blue]lectura[/]"
    console.print()
    console.print(Rule(
        f"[bold][{i}/{total}] {equipo['nombre']}[/]  [dim]{equipo['host']} · "
        f"{equipo['device_type']}[/]  {rol}",
        style="cyan",
    ))


def mostrar_estado_equipo(resultado: dict) -> None:
    if resultado["estado"] != "ok":
        console.print(Panel(f"[bold red]✗ {resultado['estado']}[/]\n[dim]El script continúa "
                            f"con el siguiente equipo.[/]", border_style="red", box=box.ROUNDED))
        return

    datos = resultado["datos"]
    sistema = datos.get("sistema", {})
    ruta = datos.get("ruta_default") or {}

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", justify="right")
    info.add_column(style="bold")
    info.add_row("Hostname", datos.get("hostname") or "—")
    info.add_row("Uptime", sistema.get("uptime") or "—")
    if sistema.get("version"):
        info.add_row("Versión", sistema["version"])
    info.add_row("Gateway", f"[yellow]{ruta.get('gateway') or 'sin ruta por defecto'}[/]")

    ifaces = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=False)
    ifaces.add_column("Interfaz")
    ifaces.add_column("IP", style="green")
    for itf in datos.get("interfaces", []):
        ifaces.add_row(str(itf.get("interfaz")), str(itf.get("ip")))

    console.print(Panel(Group(info, ifaces), title="[bold green]✓ Estado (R4)[/]",
                        border_style="green", box=box.ROUNDED))


def mostrar_cambios(cambios: dict | None) -> None:
    if not cambios:
        return
    tabla = Table(box=box.SIMPLE, header_style="bold")
    tabla.add_column("Objeto")
    tabla.add_column("Valor")
    tabla.add_column("Resultado")
    for objeto, valor, accion in cambios["pasos"]:
        color = COLOR_PASO.get(accion, "white")
        tabla.add_row(objeto, valor, f"[{color}]{accion}[/]")

    verif = cambios["verificacion"]
    if cambios["hubo_cambios"]:
        titular = "[bold yellow]⚙ Se aplicaron cambios[/]"
    else:
        titular = "[bold dim]● Sin cambios (idempotente)[/]"
    verif_txt = (
        "[green]✓ verificado con lectura posterior[/]" if verif["ok"]
        else f"[red]✗ verificación falló: {verif}[/]"
    )
    titulo = "R6 · Limpieza" if cambios["accion"] == "limpiar" else "R6 · Configuración"
    console.print(Panel(Group(Text.from_markup(titular), tabla, Text.from_markup(verif_txt)),
                        title=f"[bold]{titulo}[/]", border_style="yellow", box=box.ROUNDED))


def mostrar_comparacion_rest(rest: dict | None) -> None:
    if not rest:
        return
    if "error" in rest:
        console.print(f"  [magenta]REST:[/] [red]{rest['error']}[/]")
        return
    tabla = Table(box=box.SIMPLE, header_style="bold magenta")
    for col in ("Campo", "SSH", "REST", ""):
        tabla.add_column(col)
    for fila in rest["comparacion"]:
        marca = {True: "[green]✓[/]", False: "[red]✗[/]", None: "[dim]~[/]"}[fila["coincide"]]
        tabla.add_row(fila["campo"], str(fila["ssh"]), str(fila["rest"]), marca)
    console.print(Panel(tabla, title="[bold magenta]Extra · SSH vs REST[/]",
                        border_style="magenta", box=box.ROUNDED))


def mostrar_resumen(resultados: list[dict], ruta_reporte: Path) -> None:
    """Tabla de R5: equipo, IP, estado, cantidad de interfaces, gateway."""
    tabla = Table(title="Resumen de ejecución", box=box.ROUNDED, header_style="bold white on blue",
                  title_style="bold cyan")
    tabla.add_column("Equipo", style="bold")
    tabla.add_column("IP")
    tabla.add_column("Estado")
    tabla.add_column("Interfaces", justify="center")
    tabla.add_column("Gateway por defecto")
    tabla.add_column("Cambio R6", justify="center")

    for r in resultados:
        ok = r["estado"] == "ok"
        datos = r.get("datos") or {}
        cambios = r.get("cambios")
        r6 = "—" if not cambios else ("[yellow]aplicado[/]" if cambios["hubo_cambios"]
                                      else "[dim]sin cambios[/]")
        tabla.add_row(
            r["nombre"],
            r["host"],
            "[green]● ok[/]" if ok else f"[red]● {r['estado'].split(' (')[0][:40]}[/]",
            str(len(datos.get("interfaces", []))) if ok else "—",
            str((datos.get("ruta_default") or {}).get("gateway") or "—"),
            r6,
        )

    console.print()
    console.print(tabla)
    total_ok = sum(r["estado"] == "ok" for r in resultados)
    color = "green" if total_ok == len(resultados) else "yellow" if total_ok else "red"
    console.print(
        f"[{color}]{total_ok}/{len(resultados)} equipos OK[/]  ·  "
        f"Reporte: [underline]{ruta_reporte.name}[/]  ·  Logs: [underline]{LOGS_DIR.name}/[/]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def parsear_argumentos() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lab 1 — Inventario y configuración con Netmiko")
    p.add_argument("-i", "--inventario", default=str(BASE_DIR / "inventario.yaml"),
                   help="ruta del inventario YAML")
    p.add_argument("-n", "--numero", type=int, help="número de lista (sobrescribe el YAML)")
    grupo = p.add_mutually_exclusive_group()
    grupo.add_argument("--limpiar", action="store_true", help="eliminar solo mis objetos")
    grupo.add_argument("--solo-estado", action="store_true", help="no modificar configuración")
    p.add_argument("--rest", action="store_true", help="extra: comparar con la API REST")
    return p.parse_args()


def obtener_estudiante(inventario: dict, opciones: argparse.Namespace) -> dict:
    datos = inventario.get("estudiante") or {}
    numero = opciones.numero if opciones.numero is not None else datos.get("numero")
    if not isinstance(numero, int) or not 1 <= numero <= 254:
        raise ValueError("Defina estudiante.numero (1-254) en el YAML o use -n N")
    return {"numero": numero, "nombre": datos.get("nombre", f"Estudiante {numero}")}


def main() -> int:
    opciones = parsear_argumentos()
    try:
        inventario = cargar_inventario(Path(opciones.inventario))
        estudiante = obtener_estudiante(inventario, opciones)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as e:
        console.print(Panel(f"[bold red]{e}[/]", title="Error de inventario", border_style="red"))
        return 2

    equipos = inventario["equipos"]
    mostrar_banner(opciones, estudiante, len(equipos))

    resultados = []
    for i, equipo in enumerate(equipos, start=1):
        mostrar_encabezado_equipo(equipo, i, len(equipos))
        resultado = procesar_equipo(equipo, opciones, estudiante)
        mostrar_estado_equipo(resultado)
        mostrar_cambios(resultado["cambios"])
        mostrar_comparacion_rest(resultado["rest"])
        resultados.append(resultado)

    guardar_reporte(resultados, estudiante, REPORTE_JSON)
    mostrar_resumen(resultados, REPORTE_JSON)
    return 0 if all(r["estado"] == "ok" for r in resultados) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/]")
        sys.exit(130)
