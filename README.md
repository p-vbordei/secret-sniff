# secret-sniff

[![ci](https://github.com/p-vbordei/secret-sniff/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/secret-sniff/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/secret-sniff.svg)](https://www.npmjs.com/package/secret-sniff)
[![downloads](https://img.shields.io/npm/dm/secret-sniff.svg)](https://www.npmjs.com/package/secret-sniff)
[![bundle](https://img.shields.io/bundlejs/size/secret-sniff)](https://bundlejs.com/?q=secret-sniff)

> Scan text for credentials, API keys, and other secrets. Built around the published formats vendors use (`ghp_…`, `AKIA…`, `sk-ant-…`, PEM blocks, JWTs), not entropy guessing — so false positives stay low.

```ts
import { scan, contains, redact } from "secret-sniff";

scan("token=ghp_1234567890abcdefghij1234567890abcdefgh");
// {
//   found: true,
//   findings: [
//     { patternId: "github.token", label: "GitHub token", match: "ghp_…", index: 6, length: 40 }
//   ]
// }

contains(logLine);       // boolean

const safe = redact(logLine);
// "token=[REDACTED-github.token]"
```

## Install

```sh
npm install secret-sniff
```

Works with Node 20+, browsers, Bun, Deno. ESM + CJS.

## Why

Tools like `trufflehog` and `gitleaks` are heavy general-purpose secret scanners. For a Node app you want something tiny that:

- Catches the well-known prefixed formats (90% of leaks come from these)
- Runs in microseconds in a hot path (log redaction, pre-commit hook)
- Doesn't false-positive on UUIDs, hex strings, base64 binaries

`secret-sniff` is **format-anchored**, not entropy-guessing. If a token starts with `ghp_`, it's a GitHub token. No fuzzy heuristics, no NLP, no megabyte vocab files.

## Recipes

### Sanitize logs

```ts
import { redact } from "secret-sniff";

const log = {
  info: (msg: string) => console.log(redact(msg)),
  error: (msg: string, err: unknown) => console.error(redact(msg), err),
};

log.info(`Calling API with token ${token}`);  // ghp_… gets redacted
```

### Git pre-commit hook

```ts
import { scan } from "secret-sniff";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const stagedFiles = execSync("git diff --cached --name-only").toString().split("\n").filter(Boolean);

let leaked = false;
for (const file of stagedFiles) {
  const content = readFileSync(file, "utf8");
  const r = scan(content);
  if (r.found) {
    console.error(`${file}: ${r.findings.length} secret(s) detected`);
    for (const f of r.findings) console.error(`  ${f.label} at offset ${f.index}`);
    leaked = true;
  }
}
if (leaked) process.exit(1);
```

### CI scanner — fail build if secrets in diff

```ts
import { scan } from "secret-sniff";
import { execSync } from "node:child_process";

const diff = execSync("git diff origin/main").toString();
const r = scan(diff);
if (r.found) {
  console.error(`::error::Found ${r.findings.length} potential secret(s) in diff`);
  for (const f of r.findings) console.error(`::error::${f.label}`);
  process.exit(1);
}
```

### Express middleware — block secrets in user input

```ts
import { contains } from "secret-sniff";

app.use((req, res, next) => {
  const body = JSON.stringify(req.body);
  if (contains(body)) {
    return res.status(400).json({ error: "Possible credential in request body" });
  }
  next();
});
```

### Add custom organization patterns

```ts
import { DEFAULT_PATTERNS, scan } from "secret-sniff";

const internal = [
  ...DEFAULT_PATTERNS,
  {
    id: "internal.api-key",
    label: "internal API key",
    regex: /\bIK-[A-Z0-9]{24}\b/,
  },
];

scan(text, { patterns: internal });
```

## What it catches

| Provider | Pattern ID(s) |
|---|---|
| AWS | `aws.access-key` |
| GitHub | `github.token`, `github.fine-grained` |
| GitLab | `gitlab.pat` |
| Anthropic | `anthropic.key` |
| OpenAI | `openai.project-key`, `openai.legacy-key` |
| Slack | `slack.token`, `slack.webhook` |
| Stripe | `stripe.live-secret`, `stripe.test-secret` |
| Google | `google.api-key`, `google.oauth-token` |
| Twilio | `twilio.account-sid`, `twilio.api-key` |
| SendGrid | `sendgrid.api-key` |
| Mailgun | `mailgun.key` |
| npm | `npm.token` |
| PyPI | `pypi.token` |
| Cloudflare | `cloudflare.api-token` |
| JWT | `jwt` |
| PEM | `pem.private-key`, `ssh.private-key-header` |
| Generic | `generic.basic-auth` (URL with embedded password) |

## API

### `scan(text, opts?): { found, findings[] }`

Each finding has `patternId`, `label`, `match`, `index`, `length`.

### `contains(text, opts?): boolean`

Quick bool when you don't care about the details.

### `redact(text, opts?): string`

Replace each match with `[REDACTED-<patternId>]`. Pass `replacement` as a string or a `(finding) => string` function.

### Options

| Field | Type | Default | Meaning |
|---|---|---|---|
| `patterns` | `SecretPattern[]` | `DEFAULT_PATTERNS` | Replace or extend the built-in list |
| `ignoreCodeFences` | `boolean` | `false` | Skip matches inside fenced code blocks |

## Not in scope

- **Entropy heuristics** for unknown secret formats — they trip on UUIDs, hashes, base64 binaries. If you need that, use a dedicated scanner like `trufflehog`.
- **Validating** that a found key is live — this is a regex match, not an API call.
- **Searching git history.** This scans text. To scan a repo's history, run it over the output of `git log -p`.

## License

Apache-2.0 © Vlad Bordei
