# Lab 1 — Inventario, estado y configuración segura con Python + SSH (Netmiko)

ITIEL-13 Redes Programables · UTN · III-2026 · Daniel Saborío (N = 5)

Script `lab1_inventario.py` que:

1. Lee los equipos desde `inventario.yaml` (R1).
2. Toma las claves de variables de entorno o las pide con `getpass` (R2).
3. Se conecta por SSH con Netmiko a cada equipo; si uno falla, registra el error y sigue con los demás. Guarda un `session_log` por equipo en `logs/` (R3).
4. Recolecta hostname, uptime, interfaces con IP y ruta por defecto como diccionarios, con los comandos agrupados por `device_type` (R4).
5. Escribe `reporte_estado.json` y muestra una tabla resumen en consola (R5).
6. En el MikroTik (`rol: escritura`) asegura `lo-ssh-5` (bridge sin puertos) con `10.253.0.5/32` y un comentario con mi nombre. Consulta antes de crear, verifica después y la 2.ª ejecución muestra "sin cambios". `--limpiar` elimina solo esos objetos (R6).

Extras: Cisco IOS en el inventario (multivendor, solo lectura) y la comparación SSH vs. API REST del MikroTik (`--rest`).

## Estructura

```
├── README.md
├── requirements.txt
├── .gitignore
├── inventario.yaml        # SIN contraseñas
├── lab1_inventario.py     # script principal
├── reporte_estado.json    # salida de una ejecución
├── logs/                  # session_log de cada equipo
├── LAB01.gns3             # topología GNS3 local
└── laboratorio_local/     # preparar_host.sh (IP del host en tap0, con sudo)
```

## Laboratorio local (GNS3, sin VPN)

La topología corre en este equipo con `LAB01.gns3`:

```
host (tap0) 10.60.30.1 ── Switch1 ──┬── MikroTik ether1 10.60.30.202 ── ether2 172.16.20.1 ── PC2 .100
                                    └── R1 Fa0/0       10.60.30.203 ── Fa0/1  172.16.10.1 ── PC1 .11
```

Cloud1 enlaza Switch1 con la interfaz `tap0` del host. Al darle la IP `10.60.30.1`, el host queda en la LAN y es el gateway por defecto de los routers.

1. Abra `LAB01` en GNS3 y encienda todos los nodos.
2. Conecte el host a la LAN (pide `sudo`; hay que repetirlo cada vez que se abre el proyecto):
   ```bash
   ./laboratorio_local/preparar_host.sh
   ```
3. Solo la primera vez: configure los equipos por consola. Les pone IPs, el usuario `lab-ssh` con las claves del `.env`, SSH, la REST (https) del MikroTik y la IP estática de PC1 y PC2:
   ```bash
   python lab1_inventario.py --preparar
   ```
   La clave de `admin` del MikroTik se toma de `LAB_ADMIN_MT_LAB`; si no existe, se usa `LAB_PASS_MT_LAB`.
4. Compruebe la conexión: `nc -zv 10.60.30.202 22 && nc -zv 10.60.30.203 22`.
5. Para que PC1 y PC2 se hagan ping, agregue las rutas estáticas entre sus LAN:
   ```bash
   python lab1_inventario.py --rutas          # crea solo si falta y verifica con ping LAN a LAN
   python lab1_inventario.py --quitar-rutas   # borra solo las rutas con comentario/nombre RUTAS-LAB
   ```
   Cada router aprende la LAN del otro: el MikroTik llega a `172.16.10.0/24` por `10.60.30.203`, y el Cisco a `172.16.20.0/24` por `10.60.30.202`. Sin esas rutas, los dos mandan ese tráfico al gateway `10.60.30.1` (el host), que no conoce las redes 172.16.x.

Todos los datos de la topología (LAN, interfaces, PCs, nodos de GNS3) están en la sección `laboratorio` y en los campos `lan`, `lan_interfaz`, `uplink_interfaz` y `nodo_gns3` de cada equipo en `inventario.yaml`. `--preparar` y `--rutas` no modifican `reporte_estado.json`, y sus logs van a `logs/<equipo>-rutas.log`.

`--rutas` también escribe en el Cisco aunque tenga `rol: lectura`: el rol aplica al cambio de R6, y las rutas son parte de montar el laboratorio local.

## Instalación

Requiere Python 3.10+ y la red `10.60.30.0/24` alcanzable (ver arriba).

```bash
git clone git@github.com:DaniSaborio/LAB01_Python_Netmiko.git
cd LAB01_Python_Netmiko
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Credenciales

Ninguna clave va en el código, el YAML ni el repositorio. El script busca `LAB_PASS_<NOMBRE>`, con el nombre del equipo en mayúsculas y los guiones cambiados por `_`:

| Equipo      | Variable             |
|-------------|----------------------|
| `mt-lab`    | `LAB_PASS_MT_LAB`    |
| `cisco-lab` | `LAB_PASS_CISCO_LAB` |

```bash
export LAB_PASS_MT_LAB='...'
export LAB_PASS_CISCO_LAB='...'
```

También se pueden poner en un archivo `.env` local (está en `.gitignore`). Si la variable no existe, el script pide la clave con `getpass`.

## Ejecución

```bash
python lab1_inventario.py                # estado + cambio idempotente (R1–R6)
python lab1_inventario.py                # 2.ª vez: "sin cambios"
python lab1_inventario.py --solo-estado  # solo lectura, no toca la configuración
python lab1_inventario.py --limpiar      # elimina solo lo-ssh-5 y su IP
python lab1_inventario.py --rest         # extra: compara SSH vs. API REST
python lab1_inventario.py -n 7           # usar otro número de lista
python lab1_inventario.py --preparar     # LAB01: configuración inicial por consola
python lab1_inventario.py --rutas        # LAB01: rutas entre LAN para ping PC1 <-> PC2
```

Código de salida: `0` si todos los equipos respondieron, `1` si alguno falló, `2` si el inventario es inválido.

### Probar el manejo de errores

```bash
LAB_PASS_MT_LAB=mala python lab1_inventario.py --solo-estado
# mt-lab → "error: autenticación fallida"; el script sigue con cisco-lab
```

Con Tailscale desconectado, cada equipo queda como `error: timeout de conexión` y el reporte se genera igual.

## Inventario

`inventario.yaml` define el número de lista (`estudiante.numero`) y los equipos con los campos obligatorios `nombre`, `host`, `device_type`, `usuario` y `rol` (`lectura` o `escritura`). El script rechaza el archivo si falta un campo o si aparece un campo de credenciales (`password`, `clave`, `secret`…).

Solo se escribe en equipos con `rol: escritura` y `device_type: mikrotik_routeros`. El Cisco es de solo lectura.

## Agregar otro fabricante

Basta con añadir una entrada en `COMANDOS` (los 4 comandos) y sus parsers en `PARSERS`, ambos indexados por `device_type`. No hay `if` por equipo.

## Declaración de uso de IA

Usé Claude (Anthropic) como asistente para:

- revisar la estructura del script y los parsers de `print terse`;
- corregir casos borde (mensaje de timeout vacío, hostname del Cisco con un usuario de privilegio 1);
- diagnosticar el parser de `print terse` (los comentarios con espacios rompían la idempotencia) y el KEX `diffie-hellman-group1-sha1` del Cisco 3725, que exige `paramiko<4`;
- escribir la configuración de LAB01 en GNS3 sin VPN (`--preparar`, `--rutas` y `preparar_host.sh`);
- probar la idempotencia y `--limpiar` con un MikroTik simulado;
- redactar este README.

Revisé y entiendo todo el código entregado.
