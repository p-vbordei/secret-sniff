# secret-sniff

Scan text for credentials, API keys, and other secrets. Built around the **published formats** vendors use (`ghp_…`, `AKIA…`, `sk-ant-…`, PEM blocks, JWTs), not entropy guessing — so false positives stay low.

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

Replace each match with `[REDACTED-<patternId>]`. Pass `replacement` as a string or a `(finding) => string` function:

```ts
redact(input, { replacement: "***" });
redact(input, { replacement: (f) => `<${f.label}>` });
```

### Options

| Field | Type | Default | Meaning |
|---|---|---|---|
| `patterns` | `SecretPattern[]` | `DEFAULT_PATTERNS` | Replace or extend the built-in list |
| `ignoreCodeFences` | `boolean` | `false` | Skip matches inside fenced code blocks |

### Adding rules

```ts
import { DEFAULT_PATTERNS, scan } from "secret-sniff";

const patterns = [
  ...DEFAULT_PATTERNS,
  { id: "company.api-key", label: "internal API key", regex: /\bIK-[A-Z0-9]{24}\b/ },
];
```

## Not in scope

- **Entropy heuristics** for unknown secret formats — they trip on UUIDs, hashes, base64 binaries. If you need that, use a dedicated scanner like trufflehog.
- **Validating** that a found key is live — this is a regex match, not an API call.

## License

Apache-2.0 © Vlad Bordei
