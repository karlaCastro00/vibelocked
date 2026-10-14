
export type Rule = { name: string; re: RegExp; level: 'high' | 'warn' | 'info'; fix: string };
export const rules: Rule[] = [
  { name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g, level: 'high', fix: 'Revoke at platform.openai.com/api-keys and call OpenAI only from a server.' },
  { name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, level: 'high', fix: 'Revoke in the Anthropic Console and move calls server side.' },
  { name: 'Stripe secret key', re: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Roll the key in the Stripe Dashboard under Developers, API keys.' },
  { name: 'Stripe restricted key', re: /\brk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Roll the restricted key in the Stripe Dashboard.' },
  { name: 'Stripe webhook secret', re: /\bwhsec_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Roll the endpoint signing secret in Stripe and keep it server side.' },
  { name: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, level: 'high', fix: 'Delete and recreate it under Project Settings, API Keys. Never ship it to the browser.' },
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, level: 'high', fix: 'Deactivate and delete the key in IAM, then check CloudTrail for use.' },
  { name: 'AWS secret access key', re: /aws_?secret_?access_?key["'\s:=]+[A-Za-z0-9/+]{40}/gi, level: 'high', fix: 'Deactivate the matching access key in IAM.' },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, level: 'high', fix: 'Revoke it under GitHub Settings, Developer settings.' },
  { name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/g, level: 'high', fix: 'Revoke it in GitLab access tokens.' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, level: 'warn', fix: 'Fine in a Firebase web config if restricted. If it is a Gemini or Maps key without restrictions, restrict or rotate it in Google Cloud.' },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, level: 'high', fix: 'Revoke the token in your Slack app settings.' },
  { name: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, level: 'high', fix: 'Regenerate the incoming webhook.' },
  { name: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, level: 'high', fix: 'Delete the webhook in the channel settings and create a new one.' },
  { name: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g, level: 'warn', fix: 'If this is a Twilio key, delete it in the Twilio Console.' },
  { name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, level: 'high', fix: 'Delete it in SendGrid API Keys.' },
  { name: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, level: 'high', fix: 'Revoke it in the Resend dashboard.' },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,}\b/g, level: 'high', fix: 'Invalidate it in Hugging Face access tokens.' },
  { name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, level: 'high', fix: 'Revoke it in the Groq console.' },
  { name: 'xAI API key', re: /\bxai-[A-Za-z0-9]{60,}\b/g, level: 'high', fix: 'Revoke it in the xAI console.' },
  { name: 'Replicate token', re: /\br8_[A-Za-z0-9]{36,}\b/g, level: 'high', fix: 'Revoke it in Replicate account settings.' },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, level: 'high', fix: 'Treat the key pair as compromised and replace it.' },
  { name: 'Database URL with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:@/'"]+:[^\s@/'"]{3,}@[^\s'"]+/g, level: 'high', fix: 'Change the database password and keep the URL in server env vars only.' },
  { name: 'Stripe publishable key', re: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'info', fix: 'Publishable keys are meant for the browser.' },
  { name: 'Supabase publishable key', re: /\bsb_publishable_[A-Za-z0-9_-]{20,}/g, level: 'info', fix: 'Safe to ship if Row Level Security is on for every exposed table.' },
];

export const jwtRe = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
export const genericRe = /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([^\s"'`,;]{16,})/g;

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)));
  } catch {
    return null;
  }
}

export function mask(value: string) {
  if (value.length <= 12) return value.slice(0, 3) + '...';
  return value.slice(0, 8) + '...' + value.slice(-4);
}

function lineOf(text: string, index: number) {
  return text.slice(0, index).split('\n').length;
}

export type Finding = { name: string; level: Rule['level']; value: string; line: number; fix: string };

export function scan(text: string): Finding[] {
  const found: Finding[] = [];
  const seen = new Set<string>();
  const add = (f: Finding) => {
    const key = f.name + f.value;
    if (seen.has(key)) return;
    seen.add(key);
    found.push(f);
  };
  for (const rule of rules) {
    for (const m of text.matchAll(rule.re)) {
      add({ name: rule.name, level: rule.level, value: m[0], line: lineOf(text, m.index ?? 0), fix: rule.fix });
    }
  }
  for (const m of text.matchAll(jwtRe)) {
    const payload = decodeJwtPayload(m[0]);
    const role = payload && typeof payload.role === 'string' ? payload.role : '';
    const line = lineOf(text, m.index ?? 0);
    if (role === 'service_role') {
      add({ name: 'Supabase service role key', level: 'high', value: m[0], line, fix: 'This bypasses Row Level Security. Rotate the JWT secret or move to new API keys in Supabase, and use it only on a server.' });
    } else if (role === 'anon') {
      add({ name: 'Supabase anon key', level: 'info', value: m[0], line, fix: 'Meant for the browser, but only safe with Row Level Security on every exposed table.' });
    } else {
      add({ name: 'JSON Web Token', level: 'warn', value: m[0], line, fix: 'Check what this token grants and when it expires. Session tokens should not live in code.' });
    }
  }
  const covered = found.map((f) => f.value);
  for (const m of text.matchAll(genericRe)) {
    const value = m[2];
    if (covered.some((c) => c.includes(value) || value.includes(c))) continue;
    if (/^(?:process\.env|import\.meta\.env|\$\{|<|your|xxx|changeme|example)/i.test(value)) continue;
    add({ name: 'Possible secret in ' + m[1], level: 'warn', value, line: lineOf(text, m.index ?? 0), fix: 'If this is a real value, move it to server env vars and rotate it.' });
  }
  const order = { high: 0, warn: 1, info: 2 };
  return found.sort((a, b) => order[a.level] - order[b.level] || a.line - b.line);
}


