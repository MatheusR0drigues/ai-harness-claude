# Estrutura do Repositório

| Artefato | Localização | Regra |
| :--- | :--- | :--- |
| Código da aplicação | A definir (`harness-setup`) | Alinhar antes de criar novas pastas na raiz |
| Suíte de testes | A definir (`harness-setup`) | Espelhar a estrutura do código fonte |
| Regras locais e skills | `.claude/rules/`, `.claude/skills/<skill>/SKILL.md` | Manter `.claude/rules/*.md` abaixo de `24000` bytes |
| Hooks do Claude Code | `.claude/settings.json` | Comandos sem aspas duplas relativos a `.claude/` |
| Contexto topológico (Perfil 3) | `docs/context/<arquivo>.md` | Leitura sob demanda indexada no `CLAUDE.md`; nunca `always_on` |
| Contratos e schemas de produção | `contracts/<dominio>.*` ou `schemas/<dominio>.*` | Isolados na raiz; proibido acoplar runtime dentro de `.claude/` |
| Especificações de feature | `specs/<feature>/` | Seguir fases `Specify -> Design -> Tasks -> Implement` |
| Gates e runtime local | `scripts/harness/` | Exclusivo stdlib Python `>= 3.11`, saída `0`/`1` |
| Decisões arquiteturais | `docs/adr/` | Um arquivo por ADR aceito; não reescrever histórico |
