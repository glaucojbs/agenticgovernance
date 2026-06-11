# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
versionamento segue [SemVer](https://semver.org/lang/pt-BR/). Cada incremento diário
adiciona uma linha referenciando o item correspondente do [`ROADMAP.md`](ROADMAP.md).

## [Unreleased]

### Added

- Sistema de melhoria incremental diária: `ROADMAP.md` (backlog temático priorizado em 4
  trilhas) e `CHANGELOG.md`. Fluxo de Melhoria Diária e Definição de Pronto documentados em
  `CONTRIBUTING.md`. (ROADMAP `D0`)

### Changed

### Fixed

- Lint determinístico: `ruff` fixado em `==0.15.15` no extra `[dev]` e formatação
  reaplicada em `src/`, `tests/`, `examples/` e `evals/`. Antes, o range `ruff>=0.4`
  tornava `ruff format --check` não-reprodutível entre local e CI. (ROADMAP `C0`, PR #2)

### Security
