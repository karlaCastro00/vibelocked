import { scan } from '../src/lib/scanner.ts';
const J=(...p:string[])=>p.join('');
const r=(n:number,c='A')=>Array.from({length:n},(_,i)=>'aB3xY9kQ'[i%8]).join('');
const b64=(o:object)=>Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt=(role:string)=>`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({iss:'supabase',ref:'abcdefghijklmnop',role,iat:1700000000,exp:2000000000})}.${r(43)}`;
const cases:[string,string,string|null][]=[
['OpenAI legacy',`k = "sk-${r(20)}T3BlbkFJ${r(20)}"`,'OpenAI API key'],
['OpenAI proj',J("OPENAI_API", "_KEY=", "sk-proj-", r(74), "T3BlbkFJ", r(74)),'OpenAI API key'],
['OpenAI proj no marker',`x=sk-proj-${r(120)}`,'OpenAI API key'],
['Anthropic',J("ANTHROPIC_API", "_KEY=", "sk-ant-api03-", r(93), "AA"),'Anthropic API key'],
['Stripe sk',`sk_live_51${r(97)}`,'Stripe secret key'],
['Stripe rk',`rk_live_51${r(97)}`,'Stripe restricted key'],
['Stripe whsec',`whsec_${r(32)}`,'Stripe webhook secret'],
['Supabase sb_secret',`sb_secret_${r(22)}_${r(8)}`,'Supabase secret key'],
['Supabase service_role JWT',`SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}`,'Supabase service role key'],
['AWS id',J('AK', 'IA', 'IOSFODNN7EXAMPLE'),'AWS access key ID'],
['AWS secret',J('aws_secret', '_access_key = ', 'wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'),'AWS secret access key'],
['GitHub ghp',`ghp_${r(36)}`,'GitHub token'],
['GitHub pat',`github_pat_11${r(20)}_${r(59)}`,'GitHub token'],
['GitLab',`glpat-${r(20)}`,'GitLab token'],
['Google',`AIza${r(35)}`,'Google API key'],
['Slack token',J('xo', 'xb-', '123456789012-1234567890123-', r(24)),'Slack token'],
['Slack webhook','https://hooks.slack' + '.com/services/T' + r(8) + '/B' + r(8) + '/' + r(24),'Slack webhook URL'],
['Discord webhook',J('https://discord.com/api/', 'webhooks/', '123456789012345678/', r(68)),'Discord webhook URL'],
['Twilio','S' + 'K' + '0123456789abcdef'.repeat(2),'Twilio API key'],
['SendGrid',`SG.${r(22)}.${r(43)}`,'SendGrid API key'],
['Resend',`re_${r(8)}_${r(24)}`,'Resend API key'],
['HuggingFace',`hf_${r(34)}`,'Hugging Face token'],
['Groq',`gsk_${r(52)}`,'Groq API key'],
['xAI',`xai-${r(80)}`,'xAI API key'],
['Replicate',`r8_${r(37)}`,'Replicate token'],
['Private key','-----BEGIN OPENSSH ' + 'PRIVATE KEY-----','Private key block'],
['DB URL',J('DATABASE_URL=postgresql://', 'postgres:s3cretPass', '@', 'db.abc.supabase.co:5432/postgres'),'Database URL with password'],
['Generic',J('JWT_SEC', 'RET=', 'Zx81kQpLm29vB7cN4tR0'),'Possible secret in JWT_SECRET'],
];
const neg:[string,string,string|null][]=[
['NEG anon JWT',`VITE_SUPABASE_ANON_KEY=${jwt('anon')}`,null],
['NEG Stripe pk',`VITE_STRIPE_PK=pk_live_51${r(97)}`,null],
['NEG sb_publishable',`sb_publishable_${r(22)}_${r(8)}`,null],
['NEG plain','Hello world, this is my todo app. const skip = task-list; token count 42; askAnything sk-learn',null],
['NEG env ref','OPENAI_API_KEY=process.env.OPENAI_API_KEY_VALUE_HERE',null],
['NEG uuid','id: 550e8400-e29b-41d4-a716-446655440000',null],
];
let fail=0;
for(const [n,t,exp] of [...cases,...neg]){const f=scan(t);const bad=f.filter(x=>x.level!=='info');
 const ok= exp? f.some(x=>x.name===exp&&x.level!=='info') && bad.length===1 : bad.length===0;
 if(!ok)fail++; console.log(ok?'PASS':'FAIL',n,'|',f.map(x=>x.level+':'+x.name).join(', '));}
console.log("fails",fail); if(fail) process.exit(1);
