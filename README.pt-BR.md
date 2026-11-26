# sync_gate

English | [Português](README.pt-BR.md) | [Español](README.es.md)

O porteiro da sua máquina: os comandos pesados de vários agentes de código esperam a vez, para a memória não acabar.

![Memória com e sem o sync_gate](docs/benchmark.svg)

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

Windows 11, 16 GB de RAM, 8 núcleos (16 processadores lógicos), Docker Engine 27.5.1 via API do Docker. As seis fases usaram o mesmo espelho APT local, assinado e somente leitura, e a mesma configuração sintética de localhost para o segundo build de Next.js. O Docker executou o APT sem rede e instalou os pacotes em cada fase com `--no-cache`. Os tempos excluem os downloads prévios do APT pela Internet. O BuildKit pôde reutilizar blobs do contexto. A medição foi feita com outras sessões de agente abertas e o daemon do sync_gate ativo (sem pausa), com a guarda de contaminação ligada (`contaminated: false`), na mesma imagem base da rodada anterior. A memória do daemon é a do daemon isolado do próprio benchmark, não a do instalado na máquina. O benchmark não lança processos de agente; a memória das outras sessões abertas não foi isolada das medições de RAM do sistema. MB aqui = MiB (2^20 bytes).

<!-- s:install -->
## Instalação

Windows (PowerShell):

```powershell
irm https://gate.synclabs.team/install.ps1 | iex
```

macOS e Linux:

```sh
curl -fsSL https://gate.synclabs.team/install.sh | sh
```

Sem direitos de administrador. Só escreve nas suas pastas. Atualizar, desinstalar e recuperar: [docs/install.md](docs/install.md).

<!-- s:highlights -->
## Destaques

- Builds, testes, instalações e `docker build` esperam numa fila até a memória permitir. Comando leve nunca espera. O código de saída 75 quer dizer "ainda na fila": `sync_gate wait N` o executa depois.
- Um servidor MCP compartilhado que você adotou roda até 3 instâncias (o padrão) para todas as suas sessões, não uma por sessão.
- Cada comando de um projeto declarado pode ter o próprio banco PostgreSQL, apagado quando o comando termina: [docs/postgres.md](docs/postgres.md).
- O sandbox do Codex só usa a sua fila se você o listar em `guests`: [docs/sandbox.md](docs/sandbox.md).
- O instalador nunca pede administrador e desfaz uma rodada que falhou: [docs/install.md](docs/install.md).
- Um benchmark de proxy, com o passo a passo para rodar: [docs/benchmark.md](docs/benchmark.md).

<!-- s:quickstart -->
## Início rápido

```sh
claude plugin marketplace add sync-labs-team/sync_gate
claude plugin install sync-gate@sync_gate
sync_gate mcp adopt
```

`sync_gate mcp adopt` lista os seus servidores MCP. Adotar é pelo nome (`sync_gate mcp adopt <nome>`); nada é adotado por você.

<!-- s:agents -->
## Agentes

| Agente | O que recebe |
|---|---|
| Claude Code | plugin com gancho de sessão, uma skill e o servidor MCP |
| Codex | plugin com contexto no `SessionStart`, uma skill e o servidor MCP |
| Outros | atalhos no `PATH`, `sync_gate run -- <comando>`, `sync_gate mcp serve` |

<!-- s:limits -->
## Limites

- No Windows, os arquivos dos comandos pendentes podem ser lidos pelas contas do grupo do sandbox do Codex. Um comando pendente fica no disco até rodar, ou por até 25 horas. Um convidado em modo `elevated` que não enfileira fica sem prazo, e um marcador órfão também. Não ponha segredo na linha de comando. Mais em [SECURITY.md](SECURITY.md).
- A chave de custo (programa, até duas palavras curtas, nome da pasta) aparece em `sync_gate status`; por isso entra no contexto do agente e chega ao provedor do modelo do agente.
- Comandos do sandbox só entram na fila depois que a conta está em `guests`; antes disso rodam direto.
- No Windows, o atalho não esconde um programa que existe só como `.ps1` na hora do `sync_gate shims install`. Se um aparecer depois, ele sai com 127 e uma instrução até a próxima instalação.
- O benchmark é um proxy: os processos dos agentes não entram.

<!-- s:docs -->
## Documentação

- [Guia de instalação](docs/install.md)
- [Sandbox do Codex](docs/sandbox.md)
- [PostgreSQL compartilhado](docs/postgres.md)
- [Benchmark](docs/benchmark.md)
- [Política de segurança](SECURITY.md)

<!-- s:license -->
## Licença

MIT ou Apache-2.0, à sua escolha: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
