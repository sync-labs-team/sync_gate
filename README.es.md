# sync_gate

English | [Português](README.pt-BR.md) | [Español](README.es.md)

El portero de tu máquina: los comandos pesados de varios agentes de código esperan su turno, para que la memoria no se acabe.

![Memoria con y sin sync_gate](docs/benchmark.svg)

<!-- bench -->
proxy: heavy commands of 4 agents + 10 MCP sessions; agent processes not included

Candidate d503b62, crates tree 7a3d4ce1ca80.
median of 3 runs, range in parentheses (minimum-maximum).

| Measure | Without sync_gate | With sync_gate |
| --- | --- | --- |
| Jobs lost to memory (confirmed) | 0 (0-0) | 0 (0-0) |
| Jobs lost, memory suspected or unexplained | 0 (0-0) | 0 (0-0) |
| Jobs completed | 4 (4-4) | 4 (4-4) |
| Peak RAM | 98% (93%-99%) | 90% (88%-90%) |
| Paging file growth | 4957 MB (3750 MB-5037 MB) | 2549 MB (2521 MB-3039 MB) |
| MCP processes | 40 (40-40) | 4 (4-4) |
| MCP memory | 2323 MB (2295 MB-2366 MB) | 233 MB (232 MB-236 MB) |
| sync_gate daemon memory | - | 12 MB (12 MB-13 MB) |
| Total time | 1m16s (1m15s-1m18s) | 1m50s (1m35s-2m05s) |
| Cost per command | 13 ms (12 ms-13 ms) | 132 ms (129 ms-132 ms) |
| Complete phases | 3 of 3 | 3 of 3 |
<!-- /bench -->

Windows 11, 16 GB de RAM, 8 núcleos (16 procesadores lógicos), Docker Engine 27.5.1 mediante la API de Docker. Las seis fases usaron el mismo espejo APT local, firmado y de solo lectura, y la misma configuración sintética de localhost para la segunda compilación de Next.js. Docker ejecutó APT sin red e instaló los paquetes en cada fase con `--no-cache`. Los tiempos excluyen las descargas previas de APT por Internet. BuildKit pudo reutilizar blobs del contexto. La medición se hizo con otras sesiones de agente abiertas y el daemon de sync_gate activo (sin pausa), con la guarda de contaminación activada (`contaminated: false`), sobre la misma imagen base de la ronda anterior. La memoria del daemon es la del daemon aislado del propio benchmark, no la del instalado en la máquina. El benchmark no lanza procesos de agente; la memoria de las otras sesiones abiertas no se aisló de las mediciones de RAM del sistema. MB aquí = MiB (2^20 bytes).

<!-- s:install -->
## Instalación

Windows (PowerShell):

```powershell
irm https://gate.synclabs.team/install.ps1 | iex
```

macOS y Linux:

```sh
curl -fsSL https://gate.synclabs.team/install.sh | sh
```

Sin permisos de administrador. Solo escribe en tus carpetas. Actualizar, desinstalar y recuperar: [docs/install.md](docs/install.md).

<!-- s:highlights -->
## Destacados

- Builds, pruebas, instalaciones y `docker build` esperan en una cola hasta que la memoria lo permita. Un comando liviano nunca espera, salvo detrás de `sync_gate run`. El código de salida 75 significa "todavía en la cola": `sync_gate wait N` lo ejecuta después, con el entorno del shell que lo llama, no el original.
- Un servidor MCP compartido que adoptaste corre hasta 3 instancias (el valor por defecto) para todas tus sesiones, no una por sesión.
- Cada comando de un proyecto declarado puede tener su propia base PostgreSQL, que se borra cuando el comando termina: [docs/postgres.md](docs/postgres.md).
- El sandbox de Codex solo usa tu cola si lo listas en `guests`: [docs/sandbox.md](docs/sandbox.md).
- El instalador nunca pide administrador y deshace una ejecución que falló: [docs/install.md](docs/install.md).
- Un benchmark proxy, con los pasos para correrlo: [docs/benchmark.md](docs/benchmark.md).

<!-- s:quickstart -->
## Inicio rápido

```sh
claude plugin marketplace add sync-labs-team/sync_gate
claude plugin install sync-gate@sync_gate
sync_gate mcp adopt
```

`sync_gate mcp adopt` lista tus servidores MCP. Adoptar es por nombre (`sync_gate mcp adopt <nombre>`); nada se adopta por ti.

<!-- s:agents -->
## Agentes

| Agente | Qué recibe |
|---|---|
| Claude Code | plugin con gancho de sesión, una skill y el servidor MCP |
| Codex | plugin con contexto en `SessionStart`, una skill y el servidor MCP |
| Otros | atajos en el `PATH`, `sync_gate run -- <comando>`, `sync_gate mcp serve` |

<!-- s:limits -->
## Límites

- En Windows, los archivos de los comandos pendientes pueden ser leídos por las cuentas del grupo del sandbox de Codex. Un comando pendiente queda en el disco hasta que corre, o hasta 25 horas. Un invitado en modo `elevated` que no encola queda sin plazo, y un marcador huérfano también. No pongas un secreto en la línea de comandos. Más en [SECURITY.md](SECURITY.md).
- La clave de costo (programa, hasta dos palabras cortas, nombre de la carpeta) aparece en `sync_gate status`; por eso entra en el contexto del agente y llega al proveedor del modelo del agente.
- En Windows, el atajo no oculta un programa que existe solo como `.ps1` al ejecutar `sync_gate shims install`. Si aparece uno después, sale con 127 y una instrucción hasta la próxima instalación.
- El benchmark es un proxy: los procesos de los agentes no entran.
- Cada semana el daemon busca en GitHub una versión nueva; `status` la muestra. Se desactiva con `update_check_days = 0` ([detalles](docs/install.md#update)).

<!-- s:docs -->
## Documentación

- [Guía de instalación](docs/install.md)
- [Sandbox de Codex](docs/sandbox.md)
- [PostgreSQL compartido](docs/postgres.md)
- [Benchmark](docs/benchmark.md)
- [Política de seguridad](SECURITY.md)

<!-- s:license -->
## Licencia

MIT o Apache-2.0, a tu elección: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
