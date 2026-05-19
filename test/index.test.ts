import { describe, it, expect } from "vitest";
import { scan, contains, redact, DEFAULT_PATTERNS } from "../src/index.js";

// Test fixtures are constructed at runtime so the literal pattern never
// appears in the source file itself. This avoids tripping push-time secret
// scanners that flag literal credential-looking strings.
const FIXTURES = {
  aws: "AKIA" + "X".repeat(16),                          // AKIA + 16 chars
  gh:  "ghp_" + "X".repeat(36),
  glp: "glpat-" + "Y".repeat(20),
  ant: "sk-ant-" + "api03-" + "Z".repeat(85),
  op:  "sk-proj-" + "Q".repeat(40),
  ol:  "sk-" + "Q".repeat(48),
  gg:  "AIza" + "K".repeat(35),                          // AIza + 35 chars
  sg:  "SG." + "a".repeat(22) + "." + "b".repeat(43),
  stl: "sk_live_" + "M".repeat(24),
  stt: "sk_test_" + "N".repeat(24),
  npm: "npm_" + "L".repeat(36),
  sw:  "https://hooks.slack.com/services/T" + "A".repeat(8) + "/B" + "B".repeat(8) + "/" + "C".repeat(20),
  tw:  "AC" + "f".repeat(32),
  ba:  "postgres://user:" + "P".repeat(10) + "@localhost:5432/db",
} as const;

describe("scan: detects known credential formats", () => {
  it.each([
    [`AWS_KEY=${FIXTURES.aws}`, "aws.access-key"],
    [`token: ${FIXTURES.gh}`, "github.token"],
    [`GITLAB_TOKEN=${FIXTURES.glp}`, "gitlab.pat"],
    [FIXTURES.ant, "anthropic.key"],
    [FIXTURES.op, "openai.project-key"],
    [FIXTURES.ol, "openai.legacy-key"],
    [FIXTURES.gg, "google.api-key"],
    [FIXTURES.sg, "sendgrid.api-key"],
    [FIXTURES.stl, "stripe.live-secret"],
    [FIXTURES.stt, "stripe.test-secret"],
    [FIXTURES.npm, "npm.token"],
    [`webhook: ${FIXTURES.sw}`, "slack.webhook"],
    [FIXTURES.tw, "twilio.account-sid"],
    [FIXTURES.ba, "generic.basic-auth"],
  ])("flags pattern %#", (input, expectedId) => {
    const r = scan(input);
    expect(r.found).toBe(true);
    expect(r.findings.map((f) => f.patternId)).toContain(expectedId);
  });

  it("catches PEM private key block", () => {
    const begin = "-----BEGIN" + " RSA PRIVATE KEY-----";
    const end = "-----END" + " RSA PRIVATE KEY-----";
    const pem = [begin, "M".repeat(50), "N".repeat(50), end].join("\n");
    const r = scan(pem);
    expect(r.findings.some((f) => f.patternId === "pem.private-key")).toBe(true);
  });

  it("catches JWT token", () => {
    const jwt = ["eyJ" + "A".repeat(20), "eyJ" + "B".repeat(20), "C".repeat(40)].join(".");
    expect(scan(jwt).findings.map((f) => f.patternId)).toContain("jwt");
  });
});

describe("scan: clean input", () => {
  it.each([
    "this is a perfectly normal sentence with no secrets",
    "var x = 'hello world'",
    "",
    "AKIA but-not-followed-by-uppercase",
    "sk- short",
  ])("does not flag: %s", (input) => {
    expect(scan(input).found).toBe(false);
  });
});

describe("contains", () => {
  it("returns boolean", () => {
    expect(contains(FIXTURES.aws)).toBe(true);
    expect(contains("hello world")).toBe(false);
  });
});

describe("redact", () => {
  it("replaces matches with labeled placeholders", () => {
    const text = `AWS=${FIXTURES.aws} and GH=${FIXTURES.gh}.`;
    const out = redact(text);
    expect(out).toContain("[REDACTED-aws.access-key]");
    expect(out).toContain("[REDACTED-github.token]");
    expect(out).not.toContain(FIXTURES.aws);
    expect(out).not.toContain("ghp_");
  });

  it("supports custom replacement string", () => {
    expect(redact(`token=${FIXTURES.aws}`, { replacement: "***" })).toBe("token=***");
  });

  it("supports replacement function", () => {
    const out = redact(FIXTURES.aws, { replacement: (f) => `<${f.label}>` });
    expect(out).toBe("<AWS access key ID>");
  });

  it("returns text unchanged when nothing matched", () => {
    expect(redact("hello there")).toBe("hello there");
  });
});

describe("ignoreCodeFences", () => {
  it("skips matches inside ``` ... ```", () => {
    const text = `before\n\`\`\`\n${FIXTURES.aws}\n\`\`\`\nafter`;
    expect(scan(text).found).toBe(true);
    expect(scan(text, { ignoreCodeFences: true }).found).toBe(false);
  });
});

describe("DEFAULT_PATTERNS sanity", () => {
  it("ids are unique and regexes are valid", () => {
    const ids = new Set<string>();
    for (const p of DEFAULT_PATTERNS) {
      expect(ids.has(p.id)).toBe(false);
      ids.add(p.id);
      expect(p.regex).toBeInstanceOf(RegExp);
    }
  });
});
