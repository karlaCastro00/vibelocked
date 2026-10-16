---
title: "Supabase Storage security: buckets and RLS policies"
description: "Stop strangers from listing, downloading, or overwriting files in Supabase Storage, with policies for per-user folders and signed URLs."
pubDate: 2026-10-13
category: guide
tags:
  - supabase
  - storage
  - rls
related:
  - supabase-anon-key-vs-service-role-key
  - supabase-rls-security-checklist
  - common-vibe-coded-app-vulnerabilities
faqs:
  - question: "Is a public Supabase bucket safe?"
    answer: "A public bucket lets anyone with a file URL download that file without a token. It is fine for avatars, logos, and marketing images. It is wrong for invoices, IDs, private uploads, or anything you would not post publicly."
  - question: "Do I need RLS policies on a public bucket?"
    answer: "Yes. Public only affects downloads. Uploads, updates, deletes, and listing still go through RLS policies on storage.objects, so a careless policy can let anyone overwrite or list files."
  - question: "Does the service role key bypass Storage policies?"
    answer: "Yes. The service role or secret key bypasses RLS, including on storage.objects. Use it only in server code, never in the browser."
---

AI builders love adding file uploads: profile photos, receipts, PDFs. In Supabase those files live in Storage, and Storage access is controlled by two things: whether the bucket is public, and the RLS policies on the `storage.objects` table. Getting either wrong exposes user files.

## Public vs private, in one paragraph

A **public** bucket serves files to anyone who has the URL, with no auth check on download. A **private** bucket requires a valid JWT that passes your RLS policies, or a signed URL. In both cases, uploading, overwriting, deleting, and listing files are controlled by policies on `storage.objects`. With no policies, Storage denies those operations for the anon key.

Rule of thumb: if a file belongs to a user and is not meant to be shared, the bucket should be private.

## Check what you have now

In the Supabase dashboard open **Storage**. Each bucket shows if it is public. Then open **Storage, Policies** or run this in the SQL editor:

```sql
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects';
```

Red flags:

- A policy with `roles = {public}` or `{anon}` and `qual = true` for `SELECT`. Anyone can list and read every file in every bucket the policy covers.
- An `INSERT` or `UPDATE` policy with `with_check = true` for `anon`. Anyone can upload or replace files, including on your public bucket that serves your site images.
- No `bucket_id` condition. The policy applies to every bucket, including private ones added later.

## A safe pattern: one folder per user

Store each file under the user's id, like `receipts/<user_id>/march.pdf`, in a private bucket. Then let users touch only their own folder:

```sql
-- read own files
create policy "Users read own files"
on storage.objects for select
to authenticated
using (
  bucket_id = 'receipts'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

-- upload into own folder
create policy "Users upload own files"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'receipts'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

-- delete own files
create policy "Users delete own files"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'receipts'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
```

Upserting (overwriting) a file needs `SELECT` and `UPDATE` as well as `INSERT`. Add an `UPDATE` policy with the same condition only if your app overwrites files.

In client code, build the path from the session, never from a form field:

```js
const { data: { user } } = await supabase.auth.getUser();
await supabase.storage.from('receipts').upload(`${user.id}/${file.name}`, file);
```

## Sharing a private file: signed URLs

When a user needs to share or embed a private file, create a time limited link:

```js
const { data } = await supabase.storage
  .from('receipts')
  .createSignedUrl(`${user.id}/march.pdf`, 60 * 10); // 10 minutes
```

The request still has to pass your `SELECT` policy, so users can only sign their own files.

## Limit what gets uploaded

Set an allowed MIME type list and a file size limit on the bucket in its settings. That stops someone from using your public bucket to host large files or HTML pages on your project domain. Treat file names as untrusted and avoid serving user uploaded HTML or SVG from a public bucket. For the Next.js upload path itself (auth before tokens, MIME allow-lists, filename sanitizing, Vercel Blob client uploads), see [secure file uploads in Next.js](/guides/secure-file-uploads-nextjs-supabase-vercel-blob/).

## Keys

The anon or publishable key in your frontend is expected. The service role or `sb_secret_` key bypasses every Storage policy. If you are not sure which one your app ships, search your built JavaScript for `service_role` and `sb_secret_`, or run the [VibeLocked scanner](/scan/) on your public repo. It decodes Supabase JWTs and flags a service role key. More on this in [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/).

## Five minute test

1. Log out, open dev tools, and run `supabase.storage.from('receipts').list('')` from the console of your app. You should get an empty list or an error.
2. Log in as user A, copy a file path belonging to user B, and try `download` on it. It should fail.
3. Open a private file URL in a private window. It should not load without a signed token.

Then run the rest of the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/) for your tables.

## Sources

- [Supabase: Storage access control](https://supabase.com/docs/guides/storage/security/access-control)
- [Supabase: Public vs private buckets](https://supabase.com/docs/guides/storage/buckets/fundamentals)
- [Supabase: Storage helper functions](https://supabase.com/docs/guides/storage/schema/helper-functions)
- [Supabase: createSignedUrl](https://supabase.com/docs/reference/javascript/storage-from-createsignedurl)
