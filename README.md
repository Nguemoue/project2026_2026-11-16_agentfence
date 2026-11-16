# agentfence

CLI PHP, zéro dépendance, à lancer avant un commit. Il cherche deux choses qui fuient en ce moment depuis les agents de code :

1. Les secrets recopiés dans les fichiers de permission (`.claude/settings.local.json`, Cursor, Codex, Gemini, Continue…).
2. Les tentatives d'injection et les caractères Unicode invisibles dans les fichiers que ces agents lisent (`AGENTS.md`, `CLAUDE.md`, le README à la racine, `.github/**/*.md`).

PHP 8.1 ou plus. Un seul fichier. Rien à installer.

```bash
php agentfence.php .
php agentfence.php . --json
php agentfence.php . --fail-on=medium
```

| Code | Sens |
| --- | --- |
| 0 | Rien au-dessus du seuil. Le seuil par défaut est `high`. |
| 1 | Au moins un finding atteint le seuil. |
| 2 | Mauvais arguments, ou chemin illisible. |

## Pourquoi

En novembre 2026, [Apiiro](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again) a compté 2 539 secrets dans 1 994 dépôts publics. Une partie vient d'un geste banal : l'agent demande l'autorisation d'une commande qui contient déjà le mot de passe, on répond « Yes, and don't ask again », et la commande entière est écrite dans `.claude/settings.local.json`. Ce fichier n'est pas privé par défaut. Il part avec le commit. Le même schéma existe chez les autres agents, dans `mcp.json` et les fichiers de config locaux.

Ce script ne révoque rien et ne lit pas l'historique git. Si le secret a déjà été poussé, il est trop tard : il faut le révoquer, y compris dans les forks. Ici, le but est d'arrêter le prochain commit.

## Ce qui est signalé

`high`, et donc bloquant par défaut :

- Motifs précis : clés AWS `AKIA`/`ASIA`, jetons GitHub (`ghp_`, `github_pat_`), GitLab, Slack, Stripe live, Google, OpenAI, Anthropic, npm, SendGrid, `AccountKey` Azure, bloc de clé privée, URL de base avec mot de passe.
- Dans un fichier d'agent seulement : `sshpass -p`, `PGPASSWORD`, `MYSQL_PWD`, `--password`, `Bearer`, et les affectations `password` / `token` / `api_key`.
- `.claude/settings.local.json` présent et non ignoré par git.
- Un `.env` (pas `.env.example`) présent et non ignoré par git.

`medium`, visible mais non bloquant tant que vous ne passez pas `--fail-on=medium` :

- Phrase qui tente de détourner un agent, uniquement dans les fichiers qu'il va lire.
- Caractère de largeur nulle ou override droite-à-gauche dans ces mêmes fichiers.

Les valeurs clairement factices (`EXAMPLE`, `changeme`, `sk_live_example…`, `password`, `xxxxxxxx`) sont ignorées. Une clé live dans `.env.example` ne l'est pas.

## Ce qu'il ne fait pas

- Pas d'historique git, pas de forks, pas de révocation.
- Pas de score d'entropie. Moins de trouvailles, moins de bruit dans un vrai projet.
- Les `.env` déjà gitignorés ne sont pas lus. Les fichiers d'agent le sont quand même : le secret y est un problème même s'il n'est pas encore commité.
- `vendor/`, `node_modules/`, `.git/`, `dist/`, `build/` sont sautés. Au-delà de 1 Mo, seul le début du fichier est lu.
- L'injection n'est pas cherchée dans tout le code, seulement à la racine (`*.md`), dans `AGENTS.md` / `CLAUDE.md` / `GEMINI.md` / `SKILL.md`, sous `.github/`, et dans les dossiers d'agents.

`git` est utilisé quand le dossier est un dépôt (`check-ignore`). Sinon, seul le `.gitignore` à la racine est lu, avec un sous-ensemble des motifs (`*`, `**`, négation `!`).

## Avant le commit

```bash
#!/bin/sh
php "$(git rev-parse --show-toplevel)/agentfence.php" "$(git rev-parse --show-toplevel)"
```

En JSON, pour un job de CI : `php agentfence.php . --json`.

## English

`agentfence` is a single-file PHP 8.1+ CLI with no dependencies. It scans the working tree for secrets that coding agents persist in permission files — especially `.claude/settings.local.json`, written when someone answers "don't ask again" — and for hidden instructions in files those agents read.

It will not save you if the secret is already public. Rotate that key. This only stops the next commit.

```bash
php agentfence.php .
```

Exit `0` is clean, `1` means a finding at or above `--fail-on` (default `high`), `2` is a bad invocation.

## Tests

```bash
php tests/run.php
```

## Licence

MIT. Voir [LICENSE](LICENSE).
