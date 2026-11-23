# Setup de Hooks e Runtime — Claude Code

Este guia documenta os contratos de hooks e runtime do **Claude Code** utilizados pelo kit `ai-harness`.

## Pré-requisitos Python

| Sistema | Requisito |
| :--- | :--- |
| Windows | `python` no `PATH`, versão `>= 3.11` |
| macOS / Linux | `python3` (ou `python`) no `PATH`, versão `>= 3.11` |

Sem Python `3.11+`, o dispatcher `scripts/harness/cli.py` falha fechado em `PreToolUse` (código de saída `2` com motivo em `stderr`).

## Contrato de Execução em `.claude/settings.json`

1. **CWD = raiz do repositório:** o Claude Code executa hooks tendo a raiz do repositório como diretório de trabalho, logo os comandos apontam diretamente para `scripts/harness/cli.py`.
2. **Sem aspas duplas no comando (`ADR-0004`):** mantenha o comando limpo para portabilidade entre shells Windows e Unix. Use exatamente:
   `python scripts/harness/cli.py hook <evento> --agent claude`
   *(em ambientes Unix sem alias `python`, ajuste para `python3`)*.
3. **Estrutura dos eventos:**
   - Todos os 4 eventos suportados (`PreToolUse`, `PostToolUse`, `SessionStart`, `Stop`) vivem sob `hooks` em `.claude/settings.json`, com `"matcher": ""` nos eventos de ferramenta (`PreToolUse`, `PostToolUse`).

## Contratos de Input / Output por Evento

| Evento | Entrada (`stdin`) | Resposta Esperada |
| :--- | :--- | :--- |
| `PreToolUse` | Envia `tool_name`, `tool_input` (`file_path`, `path`, `command`, `new_string`, `edits`, `pattern`, etc.), `cwd` e `session_id`. | Negado: saída **`2`** com motivo em **`stderr`**. Permitido: saída **`0`** com **`stdout` vazio** (nunca aprova automaticamente, preservando confirmações do usuário). |
| `PostToolUse` | Mesmo envelope de ferramenta após a execução. | Limpa o journal transacional de integridade em `scripts/harness/cli.py` e termina com saída **`0`** e **`stdout` vazio**. |
| `SessionStart` | Metadados de inicialização de sessão e `cwd`. | Valida `scripts/harness/check_tamper.py` e controles; limpo emite saída `0` com **`stdout` vazio**, divergente injeta o aviso em **`stdout` simples** (texto plano). |
| `Stop` | Recebe `stop_hook_active`, `cwd` e `session_id`. | Encerrar: saída **`0`** com **`stdout` vazio**. Solicitar correção (`verify --fast`, máx. `2` continuações): `{"decision": "block", "reason": "..."}` em `stdout`. |

## Instalação Global e Recuperação de Integridade (`30s`)

- Para instalar o plugin global e regras em `~/.claude/` fora da sessão do agente, use `python scripts/harness/cli.py install-global` (verifique antes com `--dry-run`).
- Edições em módulos protegidos (`scripts/harness/hook.py`, `scripts/harness/guards.py`, `scripts/harness/payload.py`, `scripts/harness/config.py`) gravam snapshot temporário antes da escrita; se o próximo hook falhar ao importar, `scripts/harness/cli.py` restaura automaticamente o snapshot (`ADR-0008`, `ADR-0009`).

## Payloads de Referência

Os formatos aceitos pelo normalizador são verificados com fixtures determinísticas em `tests/fixtures/payloads/claude/`.

## Adoção em repositório existente

Use estas regras ao instalar o kit num repositório que já tem hooks, specs ou regras próprias. O roteiro de migração completo, com estas regras, está em `plugin/skills/harness-setup/resources/adocao.md`.

1. **Propriedade dos hooks.** Em `.claude/settings.json`, o kit é dono só dos handlers cujo comando é um dos que ele gera: `python scripts/harness/cli.py hook <evento> --agent claude` e os comandos dos packs (por exemplo `python harness/packs/research-guard/scripts/research_guard.py`). As chaves `permissions`, `$schema` e `env` e os hooks do projeto são preservados pelo `init`, que mostra `merge`. O status `conflict` aparece só quando um handler do kit foi alterado (mesmo comando com outro evento, matcher ou campo) ou quando um pack foi retirado de `--packs`. Nesse caso, nada é gravado sem `--force`; com `--force`, o `init` troca só os handlers do kit. O tamper (`check_tamper.py`) calcula o hash só dos handlers do kit.
2. **Aspas.** Os comandos do kit não têm aspas duplas (`ADR-0004`). Hooks do projeto podem citar o caminho do repositório como `"${CLAUDE_PROJECT_DIR}"`, entre aspas. Um comando que chama `scripts/harness/cli.py` segue a regra do kit mesmo fora dos handlers do kit. `disableAllHooks: true` reprova o gate `structure`, porque desliga todos os hooks do harness.
3. **`CLAUDE.md` e agentes.** O `CLAUDE.md` pode conter só `@AGENTS.md`; o `check_structure.py` procura as seções obrigatórias no `CLAUDE.md` e nos arquivos importados. Cada import fica dentro do repositório, não passa por link simbólico e aponta para um arquivo existente. Agentes sem `model` herdam o modelo da sessão. Ferramentas `mcp__<servidor>__<ferramenta>` são aceitas, exceto em `code-reviewer` e `security-auditor`.
4. **Specs legadas.** Mova as specs que não seguem o formato do kit para uma pasta `specs/_<nome>/` (exemplo: `_legado`). O `validate_spec.py --all` pula toda pasta de `specs/` cujo nome começa com `_`.
5. **Templates opcionais.** Para manter regras próprias, liste em `[init] skip_templates`, no `harness.toml`, os templates que o `init` não deve gravar. Os nomes aceitos são `product`, `structure`, `tech` e `anti-patterns`. Um nome fora dessa lista reprova o `init` e o `verify.py`. A chave vale a partir do `init` seguinte: o arquivo `.claude/rules/<nome>.md` aparece com status `skipped` e não é lido nem alterado. O `CLAUDE.md` nunca é pulado.

   ```toml
   [init]
   skip_templates = ["product", "anti-patterns"]
   ```
