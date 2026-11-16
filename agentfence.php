#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * agentfence — tripwire for secrets and prompt-injection in AI coding-agent files.
 *
 * PHP >= 8.1, no dependencies.
 * Exit 0 when nothing at or above the threshold is found, 1 when it is, 2 on bad usage.
 */

final class AgentFence
{
    public const VERSION = '1.0.0';

    private const MAX_BYTES = 1048576;

    private const SKIP_DIRS = [
        'vendor',
        'node_modules',
        'bower_components',
        '.git',
        '.hg',
        '.svn',
        '.phpunit.cache',
        '.next',
        '.nuxt',
        '.output',
        '__pycache__',
        '.venv',
        'venv',
        'dist',
        'coverage',
        'build',
        'target',
    ];

    /** @var list<string> */
    private const SKIP_EXTENSIONS = [
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'pdf', 'zip', 'gz', 'tgz',
        'bz2', '7z', 'rar', 'phar', 'exe', 'dll', 'so', 'dylib', 'woff', 'woff2',
        'ttf', 'eot', 'mp3', 'mp4', 'webm', 'sqlite', 'db', 'bin', 'wasm', 'class',
        'jar', 'lock', 'svg', 'psd',
    ];

    /**
     * High-precision token shapes. Group 0 is the secret unless "group" says otherwise.
     *
     * @var list<array{id:string,severity:string,patterns:list<string>,group:int}>
     */
    private const TOKEN_RULES = [
        [
            'id' => 'secret.aws_access_key',
            'severity' => 'high',
            'patterns' => ['~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.github_token',
            'severity' => 'high',
            'patterns' => [
                '~\bgh[pousr]_[A-Za-z0-9]{36}\b~',
                '~\bgithub_pat_[A-Za-z0-9_]{22,}~',
            ],
            'group' => 0,
        ],
        [
            'id' => 'secret.gitlab_token',
            'severity' => 'high',
            'patterns' => ['~\bglpat-[A-Za-z0-9_\-]{20,}~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.slack_token',
            'severity' => 'high',
            'patterns' => ['~\bxox[baprs]-[0-9A-Za-z-]{10,}~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.slack_webhook',
            'severity' => 'high',
            'patterns' => ['~https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.stripe_live_key',
            'severity' => 'high',
            'patterns' => ['~\b[rs]k_live_[A-Za-z0-9]{16,}~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.google_api_key',
            'severity' => 'high',
            'patterns' => ['~\bAIza[0-9A-Za-z_\-]{35}\b~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.openai_project_key',
            'severity' => 'high',
            'patterns' => ['~\bsk-proj-[A-Za-z0-9_\-]{20,}~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.anthropic_key',
            'severity' => 'high',
            'patterns' => ['~\bsk-ant-[A-Za-z0-9_\-]{20,}~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.npm_token',
            'severity' => 'high',
            'patterns' => ['~\bnpm_[A-Za-z0-9]{36}\b~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.sendgrid_key',
            'severity' => 'high',
            'patterns' => ['~\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.azure_account_key',
            'severity' => 'high',
            'patterns' => ['~AccountKey=([A-Za-z0-9+/=]{20,})~'],
            'group' => 1,
        ],
        [
            'id' => 'secret.private_key',
            'severity' => 'high',
            'patterns' => ['~-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----~'],
            'group' => 0,
        ],
        [
            'id' => 'secret.database_url',
            'severity' => 'high',
            'patterns' => ['~\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp)://([^:\s/\'"]{1,80}):([^@\s\'"]{6,})@~i'],
            'group' => 2,
        ],
    ];

    /**
     * Credential shapes that are only meaningful inside agent config.
     * Applied to the whole tree they would flag every login form.
     *
     * @var list<array{id:string,severity:string,patterns:list<string>,group:int}>
     */
    private const AGENT_RULES = [
        [
            'id' => 'secret.shell_credential',
            'severity' => 'high',
            'patterns' => ['~(?:sshpass\s+-p\s+|PGPASSWORD=|MYSQL_PWD=|--password(?:=|\s+))([^\s\'"]{6,})~i'],
            'group' => 1,
        ],
        [
            'id' => 'secret.assigned_credential',
            'severity' => 'high',
            'patterns' => ['~\b(?:password|passwd|secret|token|api[_-]?key|aws_secret_access_key)\b\s*[=:]\s*[\'"]?([^\s\'"\\\\,]{8,})~i'],
            'group' => 1,
        ],
        [
            'id' => 'secret.bearer',
            'severity' => 'high',
            'patterns' => ['~\bBearer\s+([A-Za-z0-9._\-]{20,})~'],
            'group' => 1,
        ],
    ];

    /** @var list<string> */
    private const INJECTION_PATTERNS = [
        '~\bignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules|directions)\b~i',
        '~\bdisregard (?:your |the |all )?(?:previous |prior )?(?:system |developer )?(?:prompt|instructions|rules)\b~i',
        '~\bdo not follow (?:the |your )?(?:previous |prior |system |developer )*(?:instructions|rules|prompt)\b~i',
        '~\byou are now (?:a |an )?(?:unfiltered|jailbroken)\b~i',
        '~\b(?:exfiltrate|leak) (?:the |all |any )?(?:secrets|credentials|\.env|api keys)\b~i',
        '~\bsend (?:me |the |all )?(?:contents of )?(?:\.env|secrets|credentials) to\b~i',
    ];

    /** @var array<string,string> */
    private const MESSAGES = [
        'secret.aws_access_key' => 'AWS access key id. Revoke it if this file can leave the machine.',
        'secret.github_token' => 'GitHub token. Revoke it; anyone who can read the file can use it.',
        'secret.gitlab_token' => 'GitLab personal access token.',
        'secret.slack_token' => 'Slack token.',
        'secret.slack_webhook' => 'Slack incoming webhook. Treat it as a secret.',
        'secret.stripe_live_key' => 'Stripe live key.',
        'secret.google_api_key' => 'Google API key.',
        'secret.openai_project_key' => 'OpenAI project key.',
        'secret.anthropic_key' => 'Anthropic API key.',
        'secret.npm_token' => 'npm access token.',
        'secret.sendgrid_key' => 'SendGrid API key.',
        'secret.azure_account_key' => 'Azure Storage AccountKey.',
        'secret.private_key' => 'Private key block.',
        'secret.database_url' => 'Database URL with an embedded password.',
        'secret.shell_credential' => 'Shell command in an agent rule embeds a password. This is what "don\'t ask again" saves.',
        'secret.assigned_credential' => 'Credential assignment inside an agent config file.',
        'secret.bearer' => 'Bearer token inside an agent config file.',
        'leak.local_settings_not_ignored' => 'This is the file Claude Code writes when you pick "don\'t ask again". Gitignore it. Do not commit it.',
        'leak.dotenv_not_ignored' => 'This dotenv file is not gitignored.',
        'injection.instruction_override' => 'Phrase that tries to override an agent, in a file agents read.',
        'injection.zero_width' => 'Hidden Unicode (zero-width or bidi override) in a file agents read.',
    ];

    /** @var list<string>|null relative paths, or null to walk $root */
    private ?array $only;

    /** @param list<string>|null $only */
    private function __construct(private string $root, ?array $only)
    {
        $this->only = $only;
    }

    public static function open(string $path): self
    {
        if (!file_exists($path)) {
            throw new InvalidArgumentException('Path not found: ' . $path);
        }
        $real = realpath($path);
        if ($real === false) {
            throw new InvalidArgumentException('Path not found: ' . $path);
        }
        if (is_file($real)) {
            return new self(dirname($real), [basename($real)]);
        }
        if (!is_dir($real)) {
            throw new InvalidArgumentException('Not a file or directory: ' . $path);
        }

        return new self($real, null);
    }

    /**
     * @return list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}>
     */
    public function scan(): array
    {
        $files = $this->collect();
        $ignored = $this->ignoredSet($files);
        $findings = [];
        $seen = [];

        foreach ($files as $relative) {
            $findings = array_merge($findings, $this->scanOne($relative, $ignored, $seen));
        }

        usort($findings, static function (array $a, array $b): int {
            $rank = ['high' => 0, 'medium' => 1, 'low' => 2];

            return [$rank[$a['severity']] ?? 9, $a['path'], $a['line'], $a['rule']]
                <=> [$rank[$b['severity']] ?? 9, $b['path'], $b['line'], $b['rule']];
        });

        return $findings;
    }

    public function root(): string
    {
        return $this->root;
    }

    /**
     * @return list<string>
     */
    private function collect(): array
    {
        if ($this->only !== null) {
            return $this->only;
        }

        $root = $this->root;
        try {
            $dir = new RecursiveDirectoryIterator(
                $root,
                FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
            );
            $filtered = new RecursiveCallbackFilterIterator(
                $dir,
                static function (SplFileInfo $current): bool {
                    if ($current->isLink()) {
                        return false;
                    }
                    if ($current->isDir() && in_array($current->getFilename(), self::SKIP_DIRS, true)) {
                        return false;
                    }

                    return true;
                }
            );
            $iterator = new RecursiveIteratorIterator($filtered, RecursiveIteratorIterator::LEAVES_ONLY);
        } catch (UnexpectedValueException $e) {
            throw new InvalidArgumentException('Cannot read directory: ' . $e->getMessage(), 0, $e);
        }

        $rootPrefix = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $files = [];
        foreach ($iterator as $file) {
            if (!$file instanceof SplFileInfo || !$file->isFile() || $file->isLink()) {
                continue;
            }
            $full = str_replace('\\', '/', $file->getPathname());
            $real = realpath($file->getPathname());
            if ($real !== false) {
                $realNorm = str_replace('\\', '/', $real);
                if (!str_starts_with($realNorm, $rootPrefix) && $realNorm !== rtrim($rootPrefix, '/')) {
                    continue;
                }
            }
            if (!str_starts_with($full, $rootPrefix)) {
                continue;
            }
            $relative = substr($full, strlen($rootPrefix));
            if ($relative === '' || !$this->shouldRead($relative)) {
                continue;
            }
            $files[] = $relative;
        }
        sort($files);

        return $files;
    }

    private function shouldRead(string $relative): bool
    {
        $base = strtolower(basename($relative));
        if (str_ends_with($base, '.min.js') || str_ends_with($base, '.min.css') || str_ends_with($base, '.map')) {
            return false;
        }
        $ext = strtolower(pathinfo($base, PATHINFO_EXTENSION));
        if ($ext !== '' && in_array($ext, self::SKIP_EXTENSIONS, true)) {
            return false;
        }

        return true;
    }

    /**
     * @param list<string> $files
     * @return array<string,true>|null null when git cannot answer and the caller should use the fallback per file
     */
    private function ignoredSet(array $files): ?array
    {
        if ($files === [] || !function_exists('proc_open')) {
            return null;
        }

        $probe = proc_open(
            ['git', '-C', $this->root, 'rev-parse', '--is-inside-work-tree'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $probePipes
        );
        if (!is_resource($probe)) {
            return null;
        }
        $probeOut = stream_get_contents($probePipes[1]);
        fclose($probePipes[1]);
        fclose($probePipes[2]);
        $probeCode = proc_close($probe);
        if ($probeCode !== 0 || trim((string) $probeOut) !== 'true') {
            return null;
        }

        $proc = proc_open(
            ['git', '-C', $this->root, 'check-ignore', '-z', '--stdin'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (!is_resource($proc)) {
            return null;
        }
        $payload = implode("\0", $files) . "\0";
        $written = @fwrite($pipes[0], $payload);
        fclose($pipes[0]);
        if ($written !== strlen($payload)) {
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);

            return null;
        }
        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);

        $ignored = [];
        if (is_string($out) && $out !== '') {
            foreach (explode("\0", rtrim($out, "\0")) as $path) {
                if ($path !== '') {
                    $ignored[$path] = true;
                }
            }
        }

        return $ignored;
    }

    /**
     * @param array<string,true>|null $ignored
     * @param array<string,true> $seen
     * @return list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}>
     */
    private function scanOne(string $relative, ?array $ignored, array &$seen): array
    {
        $isIgnored = $ignored !== null
            ? isset($ignored[$relative])
            : $this->fallbackIgnored($relative);

        $agentConfig = $this->isAgentConfig($relative);
        $agentDoc = $this->isAgentDoc($relative);
        $dotenv = $this->isRiskyDotenv($relative);
        $localSettings = $this->isLocalAgentSettings($relative);

        $findings = [];
        if ($localSettings && !$isIgnored) {
            $findings[] = $this->finding(
                'high',
                'leak.local_settings_not_ignored',
                $relative,
                1,
                ''
            );
        }
        if ($dotenv && !$isIgnored) {
            $findings[] = $this->finding(
                'high',
                'leak.dotenv_not_ignored',
                $relative,
                1,
                ''
            );
        }

        $scanBody = $agentConfig || !$isIgnored;
        if ($dotenv && $isIgnored) {
            $scanBody = false;
        }
        if (!$scanBody) {
            return $this->dedupe($findings, $seen);
        }

        $absolute = $this->root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        if (!is_file($absolute) || !is_readable($absolute)) {
            return $this->dedupe($findings, $seen);
        }
        $handle = fopen($absolute, 'rb');
        if ($handle === false) {
            return $this->dedupe($findings, $seen);
        }
        $content = fread($handle, self::MAX_BYTES);
        fclose($handle);
        if (!is_string($content) || $content === '') {
            return $this->dedupe($findings, $seen);
        }
        if (str_contains(substr($content, 0, 8192), "\0")) {
            return $this->dedupe($findings, $seen);
        }

        $lines = preg_split("/\R/", $content);
        if ($lines === false) {
            return $this->dedupe($findings, $seen);
        }

        foreach ($lines as $index => $line) {
            $lineNo = $index + 1;
            $scanLine = str_replace('\\/', '/', $line);
            foreach (self::TOKEN_RULES as $rule) {
                $this->applyRule($rule, $scanLine, $lineNo, $relative, $findings);
            }
            if ($agentConfig) {
                foreach (self::AGENT_RULES as $rule) {
                    $this->applyRule($rule, $scanLine, $lineNo, $relative, $findings);
                }
            }
            if ($agentDoc) {
                foreach (self::INJECTION_PATTERNS as $pattern) {
                    if (preg_match($pattern, $scanLine) === 1) {
                        $findings[] = $this->finding(
                            'medium',
                            'injection.instruction_override',
                            $relative,
                            $lineNo,
                            $this->clip($scanLine)
                        );
                        break;
                    }
                }
            }
        }

        if ($agentDoc && preg_match('//u', $content) === 1 && preg_match($this->zeroWidthPattern(), $content) === 1) {
            $lineNo = 1;
            foreach ($lines as $index => $line) {
                if (preg_match($this->zeroWidthPattern(), $line) === 1) {
                    $lineNo = $index + 1;
                    break;
                }
            }
            $findings[] = $this->finding(
                'medium',
                'injection.zero_width',
                $relative,
                $lineNo,
                ''
            );
        }

        return $this->dedupe($findings, $seen);
    }

    /**
     * @param array{id:string,severity:string,patterns:list<string>,group:int} $rule
     * @param list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}> $findings
     */
    private function applyRule(array $rule, string $line, int $lineNo, string $relative, array &$findings): void
    {
        foreach ($rule['patterns'] as $pattern) {
            if (preg_match_all($pattern, $line, $matches, PREG_SET_ORDER) < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $group = $rule['group'];
                $secret = $match[$group] ?? $match[0];
                if (!is_string($secret) || $secret === '' || $this->isBoring($secret)) {
                    continue;
                }
                $shown = $match[0];
                $snippet = str_replace($secret, $this->redact($secret), $line);
                if ($shown !== $secret && str_contains($snippet, $shown)) {
                    $snippet = str_replace($shown, $this->redact($shown), $snippet);
                }
                $findings[] = $this->finding(
                    $rule['severity'],
                    $rule['id'],
                    $relative,
                    $lineNo,
                    $this->clip($snippet)
                );
            }
        }
    }

    /**
     * @param list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}> $findings
     * @param array<string,true> $seen
     * @return list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}>
     */
    private function dedupe(array $findings, array &$seen): array
    {
        $kept = [];
        foreach ($findings as $finding) {
            $key = $finding['rule'] . "\0" . $finding['path'] . "\0" . $finding['line'] . "\0" . $finding['snippet'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $kept[] = $finding;
        }

        return $kept;
    }

    /**
     * @return array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}
     */
    private function finding(string $severity, string $rule, string $path, int $line, string $snippet): array
    {
        return [
            'severity' => $severity,
            'rule' => $rule,
            'path' => $path,
            'line' => $line,
            'message' => self::MESSAGES[$rule] ?? $rule,
            'snippet' => $this->utf8($snippet),
        ];
    }

    private function isAgentConfig(string $relative): bool
    {
        $path = strtolower(str_replace('\\', '/', $relative));
        foreach ([
            '.claude/',
            '.cursor/',
            '.codex/',
            '.gemini/',
            '.continue/',
            '.aider/',
            '.windsurf/',
            '.openai/',
            '.codeium/',
            '.clinerules/',
        ] as $dir) {
            if (str_starts_with($path, $dir) || str_contains($path, '/' . $dir)) {
                return true;
            }
        }
        $base = basename($path);

        return in_array($base, ['.cursorrules', '.clinerules', 'opencode.json'], true);
    }

    private function isAgentDoc(string $relative): bool
    {
        if ($this->isAgentConfig($relative)) {
            return true;
        }
        $path = str_replace('\\', '/', $relative);
        $base = strtolower(basename($path));
        if (in_array($base, ['agents.md', 'claude.md', 'gemini.md', 'skill.md', 'copilot-instructions.md'], true)) {
            return true;
        }
        if (preg_match('~(^|/)\.github/.+\.md$~i', $path) === 1) {
            return true;
        }

        return !str_contains($path, '/') && str_ends_with($base, '.md');
    }

    private function isLocalAgentSettings(string $relative): bool
    {
        $path = strtolower(str_replace('\\', '/', $relative));

        return basename($path) === 'settings.local.json'
            && (str_starts_with($path, '.claude/') || str_contains($path, '/.claude/'));
    }

    private function isRiskyDotenv(string $relative): bool
    {
        $base = basename($relative);
        $lower = strtolower($base);
        if (in_array($lower, ['.env.example', '.env.sample', '.env.template', '.env.dist', '.env.defaults'], true)) {
            return false;
        }

        return preg_match('/^\.env($|\.)/', $base) === 1;
    }

    private function fallbackIgnored(string $relative): bool
    {
        $gitignore = $this->root . DIRECTORY_SEPARATOR . '.gitignore';
        if (!is_file($gitignore) || !is_readable($gitignore)) {
            return false;
        }
        $text = file_get_contents($gitignore);
        if (!is_string($text)) {
            return false;
        }
        $ignored = false;
        $lines = preg_split("/\R/", $text) ?: [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $negated = false;
            if (str_starts_with($line, '!')) {
                $negated = true;
                $line = substr($line, 1);
            }
            if ($line === '') {
                continue;
            }
            if ($this->patternMatches($line, $relative)) {
                $ignored = !$negated;
            }
        }

        return $ignored;
    }

    private function patternMatches(string $pattern, string $path): bool
    {
        $dirOnly = str_ends_with($pattern, '/');
        $body = trim($pattern, '/');
        if ($body === '') {
            return false;
        }
        $quoted = preg_quote($body, '~');
        $quoted = str_replace(['\*\*', '\*', '\?'], ['.*', '[^/]*', '[^/]'], $quoted);
        if ($dirOnly) {
            return preg_match('~(^|/)' . $quoted . '(/|$)~', $path) === 1;
        }
        if (!str_contains($body, '/')) {
            return preg_match('~(^|/)' . $quoted . '$~', $path) === 1;
        }

        return preg_match('~^' . $quoted . '$~', $path) === 1;
    }

    private function isBoring(string $value): bool
    {
        $value = trim($value, "\"'`");
        if ($value === '' || strlen($value) < 6) {
            return true;
        }
        if (preg_match('/^[\$\{%<]/', $value) === 1) {
            return true;
        }
        if (preg_match('/^(password|secret|token|changeme|example|placeholder|redacted|xxx+|your[_-]?key|api[_-]?key|todo|dummy|fake|sample|null|undefined|test|testing|admin|root|foobar|pass|none)$/i', $value) === 1) {
            return true;
        }
        if (preg_match('/example|placeholder|changeme|redacted|not[_-]?a[_-]?real|insert[_-]?here/i', $value) === 1) {
            return true;
        }
        if (preg_match('/^(.)\1{7,}$/', $value) === 1) {
            return true;
        }

        return preg_match('/^[?xX*\.]{4,}$/', $value) === 1;
    }

    private function redact(string $secret): string
    {
        if (preg_match(
            '/^(gh[pousr]_|github_pat_|AKIA|ASIA|glpat-|xox[baprs]-|sk_live_|rk_live_|AIza|sk-proj-|sk-ant-|npm_|SG\.|https:\/\/hooks\.slack\.com\/services\/)/',
            $secret,
            $prefix
        ) === 1) {
            return $prefix[1] . '********';
        }

        return '********';
    }

    private function clip(string $line): string
    {
        $line = trim($line);
        if (strlen($line) <= 180) {
            return $line;
        }

        return substr($line, 0, 177) . '...';
    }

    private function utf8(string $value): string
    {
        if ($value === '' || preg_match('//u', $value) === 1) {
            return $value;
        }

        return preg_replace('/[\x80-\xFF]/', '?', $value) ?? '';
    }

    private function zeroWidthPattern(): string
    {
        $chars = '';
        foreach ([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202E] as $codepoint) {
            $chars .= $this->utf8Char($codepoint);
        }

        return '/[' . $chars . ']/u';
    }

    private function utf8Char(int $codepoint): string
    {
        if ($codepoint < 0x80) {
            return chr($codepoint);
        }
        if ($codepoint < 0x800) {
            return chr(0xC0 | ($codepoint >> 6)) . chr(0x80 | ($codepoint & 0x3F));
        }

        return chr(0xE0 | ($codepoint >> 12))
            . chr(0x80 | (($codepoint >> 6) & 0x3F))
            . chr(0x80 | ($codepoint & 0x3F));
    }
}

function agentfence_main(array $argv): int
{
    $json = false;
    $failOn = 'high';
    $path = null;

    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--json') {
            $json = true;
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, agentfence_help());

            return 0;
        }
        if ($arg === '--version' || $arg === '-V') {
            fwrite(STDOUT, AgentFence::VERSION . PHP_EOL);

            return 0;
        }
        if (str_starts_with($arg, '--fail-on=')) {
            $failOn = substr($arg, strlen('--fail-on='));
            if (!in_array($failOn, ['high', 'medium', 'low'], true)) {
                fwrite(STDERR, "Invalid --fail-on value. Use high, medium, or low.\n");

                return 2;
            }
            continue;
        }
        if (str_starts_with($arg, '-')) {
            fwrite(STDERR, "Unknown option: {$arg}\n" . agentfence_help());

            return 2;
        }
        if ($path !== null) {
            fwrite(STDERR, "Unexpected argument: {$arg}\n" . agentfence_help());

            return 2;
        }
        $path = $arg;
    }

    $path ??= getcwd();
    if ($path === false || $path === '') {
        fwrite(STDERR, "No path and no working directory.\n");

        return 2;
    }

    try {
        $fence = AgentFence::open($path);
        $findings = $fence->scan();
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, $e->getMessage() . PHP_EOL);

        return 2;
    }

    $counts = ['high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($findings as $finding) {
        $counts[$finding['severity']] = ($counts[$finding['severity']] ?? 0) + 1;
    }

    if ($json) {
        fwrite(STDOUT, json_encode([
            'tool' => 'agentfence',
            'version' => AgentFence::VERSION,
            'root' => $fence->root(),
            'counts' => $counts,
            'findings' => $findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL);
    } else {
        agentfence_print_human($fence->root(), $findings, $counts);
    }

    $rank = ['low' => 1, 'medium' => 2, 'high' => 3];
    $threshold = $rank[$failOn];
    foreach ($findings as $finding) {
        if (($rank[$finding['severity']] ?? 0) >= $threshold) {
            return 1;
        }
    }

    return 0;
}

/**
 * @param list<array{severity:string,rule:string,path:string,line:int,message:string,snippet:string}> $findings
 * @param array{high:int,medium:int,low:int} $counts
 */
function agentfence_print_human(string $root, array $findings, array $counts): void
{
    fwrite(STDOUT, 'agentfence ' . AgentFence::VERSION . PHP_EOL);
    fwrite(STDOUT, 'root: ' . $root . PHP_EOL);
    if ($findings === []) {
        fwrite(STDOUT, 'No findings.' . PHP_EOL);

        return;
    }
    fwrite(STDOUT, PHP_EOL);
    foreach ($findings as $finding) {
        $line = strtoupper($finding['severity'])
            . '  ' . $finding['rule']
            . '  ' . $finding['path'] . ':' . $finding['line'];
        fwrite(STDOUT, $line . PHP_EOL);
        fwrite(STDOUT, '      ' . $finding['message'] . PHP_EOL);
        if ($finding['snippet'] !== '') {
            fwrite(STDOUT, '      ' . $finding['snippet'] . PHP_EOL);
        }
    }
    $total = $counts['high'] + $counts['medium'] + $counts['low'];
    fwrite(STDOUT, PHP_EOL . $total . ' finding' . ($total === 1 ? '' : 's')
        . ' (' . $counts['high'] . ' high, ' . $counts['medium'] . ' medium, ' . $counts['low'] . ' low).' . PHP_EOL);
}

function agentfence_help(): string
{
    return <<<TXT
agentfence — catch secrets and prompt-injection in AI coding-agent files.

Usage:
  php agentfence.php [path] [--json] [--fail-on=high|medium|low]

Path defaults to the working directory. A file path scans just that file.
Exit 0 when clean, 1 when a finding reaches the threshold (default: high), 2 on bad usage.

The working tree is scanned. Git history is not. vendor/, node_modules/ and .git/ are skipped.
Gitignored .env files are not read. Agent config is read even when gitignored, because that
is where "don't ask again" stores the command, secret included.

TXT;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    exit(agentfence_main($argv));
}
