export interface SecretPattern {
  id: string;
  regex: RegExp;
  label: string;
}

export interface Finding {
  patternId: string;
  label: string;
  match: string;
  index: number;
  length: number;
}

export interface ScanResult {
  found: boolean;
  findings: Finding[];
}

/**
 * Built-in patterns for the most common credential formats. Patterns are anchored to the
 * formats vendors document, not to entropy heuristics, so false-positive rates stay low.
 */
export const DEFAULT_PATTERNS: readonly SecretPattern[] = Object.freeze([
  // AWS
  { id: "aws.access-key", label: "AWS access key ID", regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/ },

  // GitHub
  { id: "github.token", label: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/ },
  { id: "github.fine-grained", label: "GitHub fine-grained PAT", regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },

  // GitLab
  { id: "gitlab.pat", label: "GitLab personal access token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },

  // Anthropic
  { id: "anthropic.key", label: "Anthropic API key", regex: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/ },

  // OpenAI (project keys "sk-proj-..." and legacy "sk-..." starting with letters/digits)
  { id: "openai.project-key", label: "OpenAI project key", regex: /\bsk-proj-[A-Za-z0-9_-]{32,}\b/ },
  { id: "openai.legacy-key", label: "OpenAI legacy key", regex: /\bsk-[A-Za-z0-9]{48,64}\b/ },

  // Slack
  { id: "slack.token", label: "Slack token", regex: /\bxox[abopsr]-(?:\d{10,12}-){2,3}[A-Za-z0-9-]{20,}\b/ },
  { id: "slack.webhook", label: "Slack webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/ },

  // Stripe
  { id: "stripe.live-secret", label: "Stripe live secret key", regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/ },
  { id: "stripe.test-secret", label: "Stripe test secret key", regex: /\b(?:sk|rk)_test_[A-Za-z0-9]{24,}\b/ },

  // Google
  { id: "google.api-key", label: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "google.oauth-token", label: "Google OAuth refresh token", regex: /\b1\/\/0[0-9A-Za-z_-]{43,}\b/ },

  // Twilio
  { id: "twilio.account-sid", label: "Twilio account SID", regex: /\bAC[a-f0-9]{32}\b/ },
  { id: "twilio.api-key", label: "Twilio API key", regex: /\bSK[a-f0-9]{32}\b/ },

  // SendGrid
  { id: "sendgrid.api-key", label: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },

  // Mailgun
  { id: "mailgun.key", label: "Mailgun API key", regex: /\bkey-[a-f0-9]{32}\b/ },

  // npm
  { id: "npm.token", label: "npm token", regex: /\bnpm_[A-Za-z0-9]{36}\b/ },

  // PyPI
  { id: "pypi.token", label: "PyPI upload token", regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/ },

  // Cloudflare
  { id: "cloudflare.api-token", label: "Cloudflare API token", regex: /\b(?:Cf|cf)-[A-Za-z0-9_-]{40,}\b/ },

  // Heroku
  { id: "heroku.api-key", label: "Heroku API key", regex: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b(?=[\s\S]{0,40}heroku)/i },

  // JWT (best-effort: header.payload.signature, each base64url)
  { id: "jwt", label: "JWT token", regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },

  // Private keys (PEM)
  {
    id: "pem.private-key",
    label: "PEM private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |)PRIVATE KEY-----/,
  },

  // SSH private key one-liner (rare but seen)
  { id: "ssh.private-key-header", label: "SSH private key header", regex: /-----BEGIN OPENSSH PRIVATE KEY-----/ },

  // Generic high-confidence prefixes
  { id: "generic.basic-auth", label: "basic-auth URL", regex: /\b[a-z]{2,8}:\/\/[^\s/:@]+:[^\s/@]{4,}@[^\s/]+/i },
]);

export interface ScanOptions {
  patterns?: readonly SecretPattern[];
  /** Skip content inside fenced code blocks. Default false. */
  ignoreCodeFences?: boolean;
}

function stripCodeFences(text: string): string {
  return text.replace(/```[\s\S]*?```/g, (m) => " ".repeat(m.length));
}

/**
 * Scan text for credential/secret patterns. Never throws; returns a structured result.
 */
export function scan(text: string, opts: ScanOptions = {}): ScanResult {
  if (typeof text !== "string" || !text) return { found: false, findings: [] };
  const patterns = opts.patterns ?? DEFAULT_PATTERNS;
  const haystack = opts.ignoreCodeFences ? stripCodeFences(text) : text;
  const findings: Finding[] = [];
  for (const p of patterns) {
    const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g";
    const re = new RegExp(p.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(haystack)) !== null) {
      findings.push({
        patternId: p.id,
        label: p.label,
        match: m[0],
        index: m.index,
        length: m[0].length,
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  findings.sort((a, b) => a.index - b.index);
  return { found: findings.length > 0, findings };
}

/**
 * Quick boolean: is there at least one match?
 */
export function contains(text: string, opts?: ScanOptions): boolean {
  return scan(text, opts).found;
}

/**
 * Build a redacted version of `text` by replacing each finding with `replacement`
 * (default: `[REDACTED-<label>]`). Returns the original string if nothing matched.
 */
export function redact(
  text: string,
  opts: ScanOptions & { replacement?: string | ((f: Finding) => string) } = {},
): string {
  const result = scan(text, opts);
  if (!result.findings.length) return text;
  const replacement = opts.replacement ?? ((f: Finding) => `[REDACTED-${f.patternId}]`);
  let out = text;
  for (let i = result.findings.length - 1; i >= 0; i--) {
    const f = result.findings[i]!;
    const r = typeof replacement === "function" ? replacement(f) : replacement;
    out = out.slice(0, f.index) + r + out.slice(f.index + f.length);
  }
  return out;
}
